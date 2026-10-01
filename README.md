# mantrap

**Run untrusted commands in an OS-enforced sandbox they cannot disable.**

mantrap is a local-first CLI that executes any command inside a
deny-by-default [bubblewrap](https://github.com/containers/bubblewrap)
sandbox: only the filesystem paths you list are visible, there is no
network access, the environment is cleared except for variables you
allow, and resource limits are enforced. If the sandbox cannot be
enforced, mantrap refuses to run — it never runs exposed.

The name comes from physical security: a mantrap is a small room with
two interlocking doors. Nothing passes until it is authorized.

## Install

Requirements: Linux, Python 3.10+, `bubblewrap` (`apt install
bubblewrap` on Debian/Ubuntu).

```sh
pip install mantrap
```

Or from source:

```sh
pip install .
```

## 5-minute quickstart

```sh
mkdir demo && cd demo
mantrap init          # scaffolds ./mantrap.yaml (deny-by-default)
mantrap run -- id -u  # runs inside the sandbox
mantrap doctor        # checks the sandbox environment
```

`mantrap run` prints the workload's own stdout/stderr and exits with
its exit code, so it composes with scripts:

```sh
mantrap run -- python3 train.py > results.txt
echo "exit: $?"
```

Give the workload a writable workspace by adding an absolute path to
`fs.write` in `mantrap.yaml` — the first entry becomes the working
directory inside the sandbox.

## Commands

### `mantrap init [--force]`

Writes a commented `mantrap.yaml` to the current directory.
Refuses to overwrite an existing file unless `--force` is given.

### `mantrap run [--policy FILE] -- <cmd> [args...]`

Runs the command in the sandbox. Policy resolution order:
`--policy FILE`, then `./mantrap.yaml`, then
`~/.mantrap/mantrap.yaml` (or `$MANTRAP_DATA_DIR/mantrap.yaml`).

Before anything executes, mantrap runs a fail-closed preflight:
`bwrap` must be on `PATH` and a probe sandbox must start
successfully. Otherwise it exits 2 with a clear error and nothing
runs.

Every run appends one JSON record to `$MANTRAP_DATA_DIR/audit.log`
(default `~/.mantrap/audit.log`). If the audit log cannot be
written, the run is refused (exit 2) — an unrunnable audit trail
means nothing runs.

A wall-clock timeout kills the whole process group (SIGTERM, 5s
grace, then SIGKILL). A limit kill exits with code **124**, which
is distinct from workload failures.

### `mantrap doctor`

Checks the environment, one line per check:

```
PASS  bwrap on PATH — found /usr/bin/bwrap
PASS  user namespaces usable — bwrap probe ran
WARN  private /proc mountable — no-proc fallback will run workloads without /proc (isolation unaffected)
PASS  audit dir writable — /home/user/.mantrap
```

Exit 0 unless a check FAILs.

## Policy reference (`mantrap.yaml`)

```yaml
fs:
  read:            # read-only mounts (--ro-bind)
    - /usr
    - /bin
    - /lib
    - /lib64
  write:           # writable mounts (--bind); absolute paths only
    - /home/user/agent-workspace

env:
  allow:           # env vars copied from the caller; no wildcards
    - PATH
    - HOME

limits:
  timeout: 300     # wall-clock seconds; SIGTERM, 5s grace, SIGKILL; exit 124
  # memory: 1073741824   # RLIMIT_AS, bytes (needs prlimit(1))
  # cpu_seconds: 60      # RLIMIT_CPU, seconds (needs prlimit(1))
  # nproc: 64            # RLIMIT_NPROC (needs prlimit(1))
```

Rules: paths must be absolute, must exist, and must not escape via
`..`. Unknown keys are rejected. A name in `env.allow` that is
missing from the caller's environment is a fail-closed error.

## How isolation works

`mantrap run` builds a `bwrap` invocation equivalent to:

```
bwrap \
  --ro-bind /usr /usr ...        # fs.read entries
  --bind /workspace /workspace   # fs.write entries
  --unshare-all --unshare-net    # new mount/pid/uts/ipc/cgroup namespaces, no network
  --die-with-parent --new-session --hostname mantrap \
  --clearenv \
  --tmpfs /tmp \
  --tmpfs /dev --dev-bind /dev/null ...   # null, zero, urandom, full only
  --proc /proc \
  --setenv NAME value ...        # env.allow entries
  --chdir /workspace \
  -- <workload>
```

The workload cannot see host processes, the host network, or any
filesystem path not listed in the policy. It cannot widen its own
sandbox: policy is loaded outside, and no flag or environment
variable inside changes the `bwrap` invocation.

### The no-`/proc` fallback

In restricted environments (nested user namespaces, some CI
containers) the kernel denies mounting a private `/proc` while
every other namespace works. mantrap probes this once at startup:
if a private `/proc` is unavailable, the workload runs without
`/proc` and a warning goes to stderr. This is not a weakening —
`/proc` is an information source, not a wall; omitting it leaks
strictly less. `mantrap doctor` reports this as `WARN`.

## Limitations

- **Linux only.** Other platforms get a clear error, not a
  degraded sandbox.
- **Process isolation, not a VM.** The kernel is shared; kernel
  exploits are out of scope. For hostile-tenant separation, use a
  VM or container runtime with a hardened kernel profile.
- **No network in v0.1.** Egress control (allowlist proxy) is on
  the roadmap.
- Secrets handling in v0.1 is limited to `env.allow` passthrough;
  a proper credential broker is on the roadmap.

## License

MIT.
