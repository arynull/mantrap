"""Seccomp-BPF denylist filters, loaded into bwrap via `--seccomp FD`.

The filter is classic BPF over ``struct seccomp_data``: load the
syscall number, jump to KILL on any denylisted number, ALLOW
otherwise. Syscall numbers come from the kernel headers
(``asm/unistd_64.h`` for x86_64, ``asm-generic/unistd.h`` for
aarch64) — not from memory.

Levels (policy ``limits.seccomp``):

- ``default``: blocks the highest-risk syscalls no normal
  toolchain needs — cross-process tampering (ptrace,
  process_vm_writev), kernel attack surface (bpf, perf_event_open,
  userfaultfd), and privileged operations that are already
  impossible unprivileged but are denied in depth anyway
  (mount/umount2/pivot_root, module loading, kexec, reboot,
  swap, clock/hostname changes).
- ``strict``: default plus the merely-suspicious — personality
  (ASLR games), unshare/setns (namespace games),
  process_vm_readv, the keyctl family, fanotify_init, and
  friends. Documented as "may break toolchains": some runtimes
  legitimately call these.
- ``off``: no filter.

A blocked syscall kills the whole sandboxed process
(``SECCOMP_RET_KILL_PROCESS``) — fail-closed, no graceful fallback
for the caller to exploit.
"""

from __future__ import annotations

import platform
import struct
from pathlib import Path

# Classic BPF opcodes.
_BPF_LD_ABS_W = 0x20  # LD + W + ABS
_BPF_JEQ_K = 0x15  # JMP + JEQ + K
_BPF_RET_K = 0x06  # RET + K

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_KILL_PROCESS = 0x80000000

# Syscall numbers from the kernel headers. Only x86_64 and aarch64
# are covered; anything else fails closed at filter-build time.
_TABLES: dict[str, dict[str, int]] = {
    "x86_64": {
        "ptrace": 101,
        "personality": 135,
        "vhangup": 153,
        "adjtimex": 159,
        "acct": 163,
        "settimeofday": 164,
        "mount": 165,
        "umount2": 166,
        "swapon": 167,
        "swapoff": 168,
        "sethostname": 170,
        "setdomainname": 171,
        "create_module": 174,
        "init_module": 175,
        "delete_module": 176,
        "clock_settime": 227,
        "kexec_load": 246,
        "add_key": 248,
        "request_key": 249,
        "keyctl": 250,
        "unshare": 272,
        "perf_event_open": 298,
        "fanotify_init": 300,
        "name_to_handle_at": 303,
        "open_by_handle_at": 304,
        "clock_adjtime": 305,
        "setns": 308,
        "process_vm_readv": 310,
        "process_vm_writev": 311,
        "kcmp": 312,
        "finit_module": 313,
        "kexec_file_load": 320,
        "bpf": 321,
        "userfaultfd": 323,
        "pivot_root": 155,
        "reboot": 169,
    },
    "aarch64": {
        "umount2": 39,
        "mount": 40,
        "pivot_root": 41,
        "vhangup": 58,
        "acct": 89,
        "personality": 92,
        "unshare": 97,
        "kexec_load": 104,
        "init_module": 105,
        "delete_module": 106,
        "clock_settime": 112,
        "ptrace": 117,
        "reboot": 142,
        "sethostname": 161,
        "setdomainname": 162,
        "settimeofday": 170,
        "adjtimex": 171,
        "add_key": 217,
        "request_key": 218,
        "keyctl": 219,
        "swapon": 224,
        "swapoff": 225,
        "perf_event_open": 241,
        "fanotify_init": 262,
        "name_to_handle_at": 264,
        "open_by_handle_at": 265,
        "clock_adjtime": 266,
        "setns": 268,
        "process_vm_readv": 270,
        "process_vm_writev": 271,
        "kcmp": 272,
        "finit_module": 273,
        "bpf": 280,
        "userfaultfd": 282,
        "kexec_file_load": 294,
    },
}

# Blocked in "default": never needed by normal toolchains.
_DEFAULT_BLOCK = [
    "ptrace",
    "process_vm_writev",
    "bpf",
    "perf_event_open",
    "userfaultfd",
    "mount",
    "umount2",
    "pivot_root",
    "kexec_load",
    "kexec_file_load",
    "create_module",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "swapon",
    "swapoff",
    "clock_settime",
    "settimeofday",
    "adjtimex",
    "clock_adjtime",
    "sethostname",
    "setdomainname",
]

# Additionally blocked in "strict": may break legitimate toolchains.
_STRICT_EXTRA = [
    "personality",
    "unshare",
    "setns",
    "process_vm_readv",
    "kcmp",
    "add_key",
    "request_key",
    "keyctl",
    "fanotify_init",
    "acct",
    "vhangup",
    "name_to_handle_at",
    "open_by_handle_at",
]

LEVELS = ("off", "default", "strict")


class SeccompError(Exception):
    """The seccomp filter cannot be built for this platform/level."""


def current_arch() -> str:
    machine = platform.machine()
    # platform reports "x86_64", "aarch64", "arm64" (macOS-style), ...
    if machine == "arm64":
        machine = "aarch64"
    return machine


def blocked_numbers(level: str, arch: str | None = None) -> list[int]:
    """Syscall numbers blocked at this level on this arch."""
    if level not in LEVELS:
        raise SeccompError(f"unknown seccomp level: {level!r}")
    if level == "off":
        return []
    arch = arch or current_arch()
    table = _TABLES.get(arch)
    if table is None:
        raise SeccompError(
            f"seccomp filters are not available for arch {arch!r} "
            "(covered: x86_64, aarch64)"
        )
    names = list(_DEFAULT_BLOCK)
    if level == "strict":
        names += _STRICT_EXTRA
    try:
        return [table[name] for name in names]
    except KeyError as exc:
        raise SeccompError(
            f"no syscall number for {exc} on {arch}"
        ) from exc


def build_filter(level: str, arch: str | None = None) -> bytes:
    """Build the classic-BPF denylist program for bwrap's --seccomp."""
    numbers = sorted(set(blocked_numbers(level, arch)))
    insns: list[bytes] = []
    # LD W ABS, k=0 — syscall number is seccomp_data.nr at offset 0.
    insns.append(struct.pack("<HBBI", _BPF_LD_ABS_W, 0, 0, 0))
    kill_index = len(numbers) + 2  # LD + N JEQ + ALLOW, then KILL
    for i, nr in enumerate(numbers):
        jt = kill_index - (1 + i) - 1  # forward jump to KILL on match
        insns.append(struct.pack("<HBBI", _BPF_JEQ_K, jt, 0, nr))
    insns.append(struct.pack("<HBBI", _BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    insns.append(
        struct.pack("<HBBI", _BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS)
    )
    return b"".join(insns)


def write_filter_file(level: str, directory: Path) -> Path:
    """Write the filter bytes to a file; returns its path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"seccomp-{level}.bpf"
    blob = build_filter(level)
    if path.is_file() and path.read_bytes() == blob:
        return path
    path.write_bytes(blob)
    return path
