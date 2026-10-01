# Threat model

What mantrap protects against, what it assumes, and where the walls
are thin. No marketing: if you run hostile code, read this before
you trust the sandbox.

## Assets

1. **The host system** — files, processes, and credentials outside
   the sandbox must be unreachable from inside it.
2. **Secrets handed to the workload** (`secrets:`) — they must not
   leak to disk, to the network, or to other principals.
3. **The audit log** — the record of what ran must be tamper-evident
   (hash-chained, Ed25519-signed).
4. **Other tenants** — one sandboxed run must not affect another
   (separate mount, PID, network, and UTS namespaces per run).

## Trust boundaries

- **The policy author is trusted.** The policy file decides what
  gets mounted, what network is allowed, and which secrets are
  injected. A malicious policy is game over by design — mantrap
  enforces policy, it does not second-guess it.
- **The workload is untrusted.** Everything inside the sandbox —
  the agent binary, its dependencies, anything it downloads — is
  assumed hostile or compromised.
- **The host kernel is trusted.** See residual risks below.
- **The human is the final authority.** Approval gates (`ask`)
  exist precisely because some actions cannot be judged by policy.

## What the isolation gives you

| Mechanism | What it stops |
|---|---|
| User + mount namespaces (`bwrap --unshare-all`) | The workload sees only what the policy mounts; host paths are not reachable, even via symlink tricks (verified by `test_symlink_cannot_escape_write_mount`). |
| Read-only binds for `fs.read` | Mounted inputs cannot be modified (`EROFS`). |
| Network namespace (`--unshare-net`, default) | No sockets at all in `network.mode: none`. |
| Filtering egress proxy (allowlist mode) | Only allowlisted domains/ports; private-IP guard; cloud-metadata endpoints blocklisted even over an explicit allowlist entry. A 302 to `169.254.169.254` arrives as a fresh request and is denied. |
| Seccomp-BPF denylist (`limits.seccomp`, default on) | `ptrace`, `process_vm_writev`, `bpf`, `perf_event_open`, `userfaultfd`, mount/module/reboot/clock syscalls → the caller is killed with `SIGSYS`. Namespace games (`unshare`, `setns`, `personality`) additionally blocked under `strict`. |
| `RLIMIT_CORE=0` (hard) | A crashed workload cannot persist its environment (which carries secrets) to a core file. |
| Process-group kill on timeout | `SIGTERM` to the whole group, 5s grace, then `SIGKILL`. A double-forking workload that ignores `SIGTERM` still dies (verified by `test_timeout_kills_double_forking_workload`). |
| `--die-with-parent`, `--new-session` | No orphans, no TIOCSTI-style terminal injection. |
| Hash-chained, signed audit log | Silent modification of history is detectable (`audit --verify`). |

## Residual risks (accepted, documented)

- **Shared kernel.** Namespaces and seccomp are kernel-enforced;
  a kernel privilege-escalation vulnerability breaks the model.
  mantrap does not use VMs. If your threat model includes
  kernel 0-days, run mantrap itself inside a VM.
- **Side channels.** CPU cache timing, `perf`-style counters
  (blocked by seccomp, but coarse timers remain), and resource-
  usage oracles are not addressed.
- **`/proc/<pid>/environ` inside the sandbox.** Secrets travel in
  the workload's environment; any process in the same sandbox can
  read another's environ via `/proc` (same-UID ptrace rules).
  The sandbox boundary is the unit of trust for secrets — do not
  run mutually untrusted processes in one sandbox and expect
  secret separation between them.
- **DNS rebinding.** The proxy resolves and checks the records
  seen at request time; a name whose records change mid-session
  is only checked per request.
- **Covert channels via allowed egress.** An allowlisted domain
  is a data-exfiltration channel by definition. Allowlists are
  trust decisions, not walls.
- **Resource exhaustion.** `limits.memory/cpu_seconds/nproc`
  bound the workload, but the audit log and snapshots grow on
  the host; monitor disk.
- **The metadata blocklist is advisory for exotic clouds.** The
  well-known endpoints (AWS/GCP/Azure/Alibaba IPv4+IPv6 literals
  and GCP hostnames) are blocked; a cloud with an undocumented
  metadata address is not.
- **Seccomp is a denylist, arch-specific.** Filters exist for
  x86_64 and aarch64; other architectures fail closed. New
  syscalls in future kernels are allowed by default.
- **`strict` may break toolchains.** Debuggers, profilers, and
  some language runtimes legitimately use the strict-only
  syscalls. `default` is the tested balance.

## Non-goals

- Protecting the workload from the host (the host is trusted).
- Malware analysis of kernel exploits (use a VM with snapshots).
- Windows/macOS (Linux-only; `bwrap` is Linux).
- Preventing the policy author from harming themselves.
- Legal compliance by itself — see `docs/EU_AI_ACT.md` for how
  the audit log and gates map to regulatory obligations.
