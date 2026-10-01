"""bubblewrap sandbox construction and execution.

The sandbox is deny-by-default: only policy-listed filesystem paths
are bound in, the network is always unshared, and the environment is
cleared except for explicitly allowed variables.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time

from .policy import Policy

BWRAP = "bwrap"

# Minimal device nodes bound into the sandbox. `--dev /dev` would
# expose every host device node, so instead we mount a fresh tmpfs on
# /dev and bind only the stateless pseudo-nodes a normal workload
# needs (null/zero/urandom/full). No disks, no input devices, no TPM.
DEV_BINDS = ("/dev/null", "/dev/zero", "/dev/urandom", "/dev/full")

NO_PROC_WARNING = (
    "warning: private /proc unavailable in this environment; "
    "continuing without it (mount/PID/net isolation unaffected)"
)

# Exit code used when a resource limit (wall-clock timeout) kills the
# workload. 124 mirrors the conventional timeout(1) code so a limit
# kill cannot be confused with a normal workload failure (e.g. 137
# for SIGKILL from inside).
TIMEOUT_EXIT_CODE = 124

# Grace period after SIGTERM before escalating to SIGKILL.
TERM_GRACE_S = 5.0

# Bindings the startup probes need so the probe binary can execute.
# bwrap does not implicitly carry host libraries; the probe must bind
# the runtime paths explicitly (same reason policies normally list
# /usr, /bin, /lib, /lib64 in fs.read).
PROBE_BINDS = ("/usr", "/bin", "/lib", "/lib64")


class SandboxError(RuntimeError):
    """Raised when the sandbox cannot be started (fail-closed)."""


def find_bwrap() -> str:
    """Locate the bwrap binary on PATH or raise SandboxError."""
    path = shutil.which(BWRAP)
    if path is None:
        raise SandboxError(
            f"bubblewrap ({BWRAP}) not found on PATH; "
            "install bubblewrap to use mantrap "
            "(e.g. `apt install bubblewrap`)"
        )
    return path


def probe_userns(bwrap: str, with_proc: bool = False) -> bool:
    """Check that user namespaces work by running `true` in a sandbox."""
    cmd = [bwrap]
    for p in PROBE_BINDS:
        if os.path.exists(p):
            cmd += ["--ro-bind", p, p]
    cmd += ["--unshare-all"]
    if with_proc:
        cmd += ["--proc", "/proc"]
    cmd += ["/usr/bin/true"]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except OSError:
        return False
    return result.returncode == 0


def preflight() -> str:
    """Fail-closed startup checks. Returns the bwrap path.

    Raises SandboxError (the caller maps it to exit 2) when bwrap is
    missing or user namespaces are unusable. Nothing runs in that
    case. The probe intentionally omits `--proc /proc`: proc mounting
    is the portable subset check, and proc availability is decided
    separately (see run_workload).
    """
    bwrap = find_bwrap()
    if not probe_userns(bwrap, with_proc=False):
        raise SandboxError(
            "user namespaces are not usable: the bwrap probe "
            "(`bwrap --unshare-all true`) failed; the sandbox cannot "
            "be enforced, so nothing will run"
        )
    return bwrap


def proc_available(bwrap: str) -> bool:
    """True when a private /proc can be mounted in this environment."""
    return probe_userns(bwrap, with_proc=True)


def build_bwrap_argv(
    bwrap: str, policy: Policy, workload: list[str], with_proc: bool = True
) -> list[str]:
    """Build the bwrap command for a validated policy + workload."""
    cmd = [bwrap]
    for path in policy.fs_read:
        cmd += ["--ro-bind", path, path]
    for path in policy.fs_write:
        cmd += ["--bind", path, path]
    cmd += [
        "--unshare-all",
        "--unshare-net",
        "--die-with-parent",
        "--new-session",
        "--hostname",
        "mantrap",
        "--clearenv",
    ]
    cmd += ["--tmpfs", "/tmp"]
    cmd += ["--tmpfs", "/dev"]
    for node in DEV_BINDS:
        if os.path.exists(node):
            cmd += ["--dev-bind", node, node]
    if with_proc:
        cmd += ["--proc", "/proc"]
    for name in policy.env_allow:
        if name not in os.environ:
            raise SandboxError(
                f"policy requires env var {name!r} in 'env.allow' but it "
                "is not set in the caller's environment; refusing to run"
            )
        cmd += ["--setenv", name, os.environ[name]]
    # A minimal PATH keeps toolchains working when the usual
    # locations are bound in (policies normally include them).
    cmd += ["--setenv", "PATH", "/usr/bin:/bin"]
    if policy.fs_write:
        cmd += ["--chdir", policy.fs_write[0]]
    else:
        cmd += ["--chdir", "/tmp"]
    cmd += ["--", *workload]
    return cmd


def prlimit_prefix(policy: Policy) -> list[str]:
    """prlimit(1) argv prefix for RLIMIT_AS/CPU/NPROC, if configured."""
    prlimit = shutil.which("prlimit")
    configured = (
        policy.memory is not None
        or policy.cpu_seconds is not None
        or policy.nproc is not None
    )
    if not configured:
        return []
    if prlimit is None:
        raise SandboxError(
            "policy sets resource limits but `prlimit` was not found "
            "on PATH; refusing to run without enforced limits"
        )
    prefix: list[str] = [prlimit]
    if policy.memory is not None:
        prefix += [f"--as={policy.memory}"]
    if policy.cpu_seconds is not None:
        prefix += [f"--cpu={policy.cpu_seconds}"]
    if policy.nproc is not None:
        prefix += [f"--nproc={policy.nproc}"]
    prefix += ["--"]
    return prefix


def spawn(
    argv: list[str], timeout: int | float
) -> tuple[int, bool, float]:
    """Run argv with a wall-clock timeout.

    On expiry the whole process group gets SIGTERM, a grace period,
    then SIGKILL. Returns (exit_code, killed_by_limit, duration_s).
    The child inherits this process's stdio so workload output
    passes through untouched.
    """
    start = time.monotonic()
    proc = subprocess.Popen(argv, start_new_session=True)
    try:
        proc.wait(timeout=timeout)
        return proc.returncode, False, time.monotonic() - start
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=TERM_GRACE_S)
        return TIMEOUT_EXIT_CODE, True, time.monotonic() - start
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    proc.wait()
    return TIMEOUT_EXIT_CODE, True, time.monotonic() - start


def run_workload(
    bwrap: str,
    policy: Policy,
    workload: list[str],
    emit_warning=None,
) -> tuple[int, bool, float, bool]:
    """Run the workload exactly once, with the no-/proc fallback.

    The fallback is decided once at startup from the environment (a
    cheap `true` probe), never by the workload: if a private /proc
    cannot be mounted here, the workload runs without it and a
    warning goes to stderr. Omitting /proc leaks strictly less, so
    this is not a fail-closed violation (/proc is an information
    source, not a wall). Returns (exit_code, killed_by_limit,
    duration_s, used_proc_fallback).
    """
    prefix = prlimit_prefix(policy)
    if proc_available(bwrap):
        argv = build_bwrap_argv(bwrap, policy, workload, with_proc=True)
        code, killed, duration = spawn([*prefix, *argv], policy.timeout)
        return code, killed, duration, False
    if emit_warning is None:
        print(NO_PROC_WARNING, file=sys.stderr)
    else:
        emit_warning(NO_PROC_WARNING + "\n")
    argv = build_bwrap_argv(bwrap, policy, workload, with_proc=False)
    code, killed, duration = spawn([*prefix, *argv], policy.timeout)
    return code, killed, duration, True
