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
bubblewrap` on Debian/Ubuntu), `rsync` (for snapshots).

From source:

```sh
git clone https://github.com/rayanalpha/mantrap
cd mantrap
pip install .
```

A PyPI release (`pip install mantrap`) is planned; until then,
install from source as above.

Verify the install:

```sh
mantrap --version   # 1.3.0
mantrap doctor      # one line per environment check
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

## Examples

### Run an agent script

```sh
$ cat > agent.py <<'EOF'
import json, sys
print(json.dumps({"agent": "demo", "did": sys.argv[1], "sandboxed": True}))
EOF
$ mantrap run -- python3 agent.py "summarize logs"
{"agent": "demo", "did": "summarize logs", "sandboxed": true}
```

The run is audit-logged with its exit code and duration:

```sh
$ mantrap audit --json | python3 -c \
    "import json,sys; r=json.loads(sys.stdin.readlines()[-1]); \
     print(r['type'], 'exit', r['exit_code'])"
run exit 0
```

### Allowlist network egress (e.g. PyPI)

```yaml
# pypi.yaml
network:
  mode: allowlist
  allow_domains: [pypi.org, "*.pythonhosted.org"]
  allow_ports: [443]
```

The workload reaches only listed domains; everything else gets a
403 and a `net.deny` audit record. (Transcript below uses a local
server on loopback with `allow_private_ips: true` — same code
path, reproducible anywhere.)

```sh
$ mantrap run --policy pypi.yaml -- \
    curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:18901/agent.py
HTTP 200
$ mantrap run --policy pypi.yaml -- \
    curl -s -w "\nHTTP %{http_code}\n" http://127.0.0.1:18901/agent.py
forbidden: not_allowlisted

HTTP 403
$ mantrap audit --json | python3 -c "
import json, sys
for line in sys.stdin:
    r = json.loads(line)
    if r.get('type') in ('net.allow', 'net.deny'):
        print(r['type'], '->', r.get('reason'))" | tail -2
net.allow -> ok
net.deny -> not_allowlisted
```

### Gate a risky tool (curl) behind approval

```yaml
# gate.yaml
gates:
  - match: {exec.path: /usr/bin/curl}
    action: ask
    description: "let the workload fetch with curl?"
```

In CI there is no terminal, so `--yes` denies every ask
fail-closed — the workload never starts, and the decision is
audited:

```sh
$ mantrap run --yes --policy gate.yaml -- curl -s http://example.com
error: denied by gate-0: exec curl
$ echo $?
2
```

With a terminal, the prompt pauses the workload (`SIGSTOP`)
until you answer `once` / `always` / `deny`.

### Roll back a bad run

```sh
$ echo hello > precious.txt
$ mantrap run --auto-rollback -- sh -c 'echo corrupted > precious.txt && exit 3'
mantrap: snapshotted workspace -> e7174785/20261001-135544-581999
mantrap: run failed; workspace rolled back to e7174785/20261001-135544-581999 (1 files)
$ echo $?
3
$ cat precious.txt
hello
```

The workload's exit code (3) still propagates; the workspace is
exactly as it was, verified against the snapshot manifest.

## Commands

### `mantrap init [--force]`

Writes a commented `mantrap.yaml` to the current directory.
Refuses to overwrite an existing file unless `--force` is given.

### `mantrap run [--policy FILE] [--dry-run] -- <cmd> [args...]`

Runs the command in the sandbox. Policy resolution order:
`--policy FILE`, then `./mantrap.yaml`, then
`~/.mantrap/mantrap.yaml` (or `$MANTRAP_DATA_DIR/mantrap.yaml`).

Before anything executes, mantrap runs a fail-closed preflight:
`bwrap` must be on `PATH` and a probe sandbox must start
successfully. Otherwise it exits 2 with a clear error and nothing
runs. Secret sources are also resolved before anything starts: a
missing secret fails closed with exit 2 before the sandbox is
created.

Every run appends one JSON record to `$MANTRAP_DATA_DIR/audit.log`
(default `~/.mantrap/audit.log`). If the audit log cannot be
written, the run is refused (exit 2) — an unrunnable audit trail
means nothing runs.

A wall-clock timeout kills the whole process group (SIGTERM, 5s
grace, then SIGKILL). A limit kill exits with code **124**, which
is distinct from workload failures.

`--dry-run` loads the policy and resolves secrets, then prints the
resolved policy with secret values masked (`*** (N chars)`), the
parsed `gates:` rules, and the full bwrap command with secret
values masked — without executing anything, starting the proxy, or
writing an audit record. A missing secret still fails closed
(exit 2).

### `mantrap run [--yes] [--approve-all] ...`

`run` also takes the approval-gate flags (see Approval gates
below): `--yes` denies every `ask` gate without prompting
(for CI; fail-closed), `--approve-all` allows every `ask` gate
without prompting (logged; discouraged — prints a stderr warning
on every run). The two flags together are a usage error (exit 2).

### `mantrap exec [--add-write PATH] ... -- <cmd> [args...]`

`exec` is `run` plus per-run writable mounts: `--add-write PATH`
(repeatable) grants the workload a writable mount for that run
only. Each path is validated exactly like `fs.write` (absolute,
no `..`, must exist) and is never written back to the policy
file. Approval gates evaluate the final mount list, so a gate can
still deny an `--add-write` path.

### `mantrap doctor`

Checks the environment, one line per check:

```
PASS  bwrap on PATH — found /usr/bin/bwrap
PASS  user namespaces usable — bwrap probe ran
WARN  private /proc mountable — no-proc fallback will run workloads without /proc (isolation unaffected)
PASS  audit dir writable — /home/user/.mantrap
```

Exit 0 unless a check FAILs.

### `mantrap keygen [--rotate]`

Creates the Ed25519 signing key for the tamper-evident audit log
(see below): `~/.mantrap/signing.key`, mode 0600, generated from
the OS CSPRNG. The implementation is vendored pure Python — no new
runtime dependency. Refuses to overwrite an existing key; use
`--rotate` to replace it. Rotation appends a `key.rotate` audit
record chaining the old key id to the new one, so signatures made
with the old key stay verifiable forever. The old key file is kept
as `signing.key.prev` (0600).

Loading the key is fail-closed on permissions: a key file
readable by group or other is treated as compromised and refused.

### `mantrap audit [--verify] [--since TS] [--json]`

Shows the audit log (pretty-printed by default, one line per
record; `--json` prints one JSON object per line; `--since`
filters to records at or after an ISO-8601 timestamp).
`--verify` re-checks the hash chain and every signature and exits
1 naming the first broken record:

```
$ mantrap audit --verify
audit log verified: 57 records, 1 signatures, chain intact
```

**Verify-on-start.** Every `run`/`exec` re-verifies the audit
chain before anything starts (secrets, snapshot, proxy, bwrap):
the hash links from the tip back to the most recent signature,
plus that signature itself — transitively covering the whole
log. A tampered history refuses the run with exit 2 and names
the first broken record; nothing is appended, the workload never
starts. `--dry-run` is exempt (it touches no audit state).
Alongside the log, mantrap keeps a `audit.tip` sentinel
(record count + tip hash, 0600): deleting or truncating the log
while the rest of the state dir survives is caught the same way.
The honest limit: wiping the entire state dir is
indistinguishable from a fresh install — the sentinel guards
partial deletion/truncation, not total erasure.

The log is size-capped (`limits.audit_max_mb`, default 512 MB);
when the cap would be crossed the run exits 2 with a remedy
message — archive with `mantrap audit --json`, then rotate or
truncate `~/.mantrap/audit.log`. The proxy denies new connections
instead of proxying them unaudited.

### `mantrap snapshot [--policy FILE] [--message MSG]`

Snapshots the policy's first writable mount (host-side, via
`rsync -a --delete`) into
`~/.mantrap/snapshots/<policy-sha8>/<timestamp>/`, with a manifest
of every file's size and SHA-256. Needs `rsync` on `PATH` and at
least one `fs.write` mount (or `exec --add-write`). Prints the
snapshot id, e.g. `efbf990c/20261001-133235-393685`, and writes a
`snapshot.create` audit record.

### `mantrap snapshots [--json]` / `mantrap rollback <snap-id> [--dry-run]`

`snapshots` lists snapshots newest-first. `rollback` restores the
workspace from a snapshot (`--dry-run` shows the file-level diff —
`added`/`modified`/`deleted` — without changing anything). The
restore is verified against the manifest afterwards, and a
`snapshot.rollback` audit record is written.

### `mantrap run --snapshot [--auto-rollback] ...`

`--snapshot` takes a pre-run snapshot of the first `fs.write`
workspace (ignored with `--dry-run`). If the workload then exits
non-zero, mantrap prints a rollback hint with the snapshot id;
`--auto-rollback` (implies `--snapshot`) restores the snapshot
automatically instead, and the restore is audit-logged. The
workload's exit code still propagates.

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

secrets:           # credential broker: NAME -> exactly one source
  GH_TOKEN: {env: GH_TOKEN}            # from mantrap's own environment
  API_KEY: {file: /home/user/.secrets/api_key}  # 0600/0400 file, 1st line
  DB_PASS: {keyring: myservice/dbuser} # needs 'secretstorage' (optional)

limits:
  timeout: 300     # wall-clock seconds; SIGTERM, 5s grace, SIGKILL; exit 124
  # memory: 1073741824   # RLIMIT_AS, bytes (needs prlimit(1))
  # cpu_seconds: 60      # RLIMIT_CPU, seconds (needs prlimit(1))
  # nproc: 64            # RLIMIT_NPROC (needs prlimit(1))
  seccomp: default  # off | default | strict — syscall denylist (see below)
  audit_max_mb: 512  # audit log size cap in MB; run/exec refuse to start
                     # when full (fail-closed); 0 disables the cap

network:
  mode: none           # none | host | allowlist
  allow_domains: []    # e.g. [pypi.org, "*.pythonhosted.org"]
  allow_plain_http: false  # plain http:// through the proxy; default deny
  allow_ports: [443]   # CONNECT targets restricted to these ports
  dns: host            # host | off (off: only literal-IP entries work)
  dns_pin_ttl: 60      # seconds a resolved name stays pinned to its IP
                       # set (anti-DNS-rebinding); integer >= 0, 0 disables
                       # pinning (per-request resolution, the old behavior)
  allow_private_ips: false  # default deny: blocks SSRF to 127.0.0.0/8,
                           # 10/8, 169.254.169.254, ...

gates:                 # approval gates: the mantrap interlock
  - match: {exec.path: /usr/bin/curl}  # glob on the binary path
    action: ask                        # allow | deny | ask
  - match: {net.domain: "*.internal"}  # case-insensitive glob
    action: deny
  - match: {fs.write: /data}          # absolute path prefix
    action: ask
```

Rules: paths must be absolute, must exist, and must not escape via
`..`. Unknown keys are rejected. A name in `env.allow` that is
missing from the caller's environment is a fail-closed error. A
secret NAME may not also appear in `env.allow` — one variable, one
source of truth. Secret names must match `[A-Za-z_][A-Za-z0-9_]*`.

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

## Syscall filtering (seccomp)

On top of namespaces, every workload runs under a classic-BPF
seccomp denylist passed to `bwrap --seccomp`. The blocked call is
killed with `SIGSYS` — fail-closed, no fallback. Three levels via
`limits.seccomp`:

- `default` (recommended): blocks the calls that break out of or
  observe the sandbox — `ptrace`, `process_vm_writev`, `bpf`,
  `perf_event_open`, `userfaultfd`, `mount`/`umount2`/
  `pivot_root`, module loading, `kexec`, `reboot`, `swapon`/
  `swapoff`, clock/hostname changes. Ordinary toolchains
  (compilers, interpreters, build tools) run fine under it.
- `strict`: everything in `default`, plus `personality`,
  `unshare`, `setns`, `process_vm_readv`, the `keyctl` family,
  `fanotify_init`, and friends. Stronger, but debuggers,
  profilers, and some language runtimes legitimately need these —
  expect breakage and use it only for workloads you have tested.
- `off`: no filter. For exotic runtimes; the namespaces,
  read-only mounts, and network policy still apply.

The filter is generated deterministically (same level → same
bytes) and cached at `$MANTRAP_DATA_DIR/seccomp-<level>.bpf`.
Filters exist for x86_64 and aarch64; any other architecture is a
fail-closed error, never a silent skip. A blocked syscall shows
up as the workload dying from `SIGSYS` (exit code 159).

```sh
$ mantrap run -- python3 -c "import ctypes; ctypes.CDLL(None).ptrace(0,0,0,0)"
# killed by SIGSYS — exit code 159
```

## Network control

`network.mode` defaults to `none`: `--unshare-net`, no route out,
identical to v0.1. `host` keeps the host network namespace (every
run prints a stderr warning; explicit opt-in only). `allowlist`
gives filtered egress through a host-side filtering proxy:

```
workload --TCP--> 127.0.0.1:18080 --unix-sock--> P1 --allowlisted--> internet
(sandbox)         (relay R,        ($DATA_DIR/       (filtering
                   in-sandbox)      proxy.sock)       proxy, host)
```

Why this is unbypassable without privileges:

- `--unshare-net` stays on: the sandbox has no route anywhere.
  The relay's loopback port is the *only* reachable TCP endpoint.
- The relay only splices bytes to P1 over the bind-mounted unix
  socket; it cannot be reconfigured from inside (and
  `--cap-drop CAP_NET_ADMIN,CAP_NET_RAW` removes the caps that
  could change that).
- P1 checks the allowlist **before** any DNS or upstream contact:
  exact + `*.suffix` matching (a suffix never matches the bare
  domain), case-insensitive, IDNA-aware; IP literals only when
  the literal itself is listed. Misses get 403 and a `net.deny`
  audit record.
- Default-deny extras: plain HTTP needs `allow_plain_http: true`;
  `CONNECT` is restricted to `allow_ports` (default `[443]`);
  loopback/private/link-local upstream IPs are refused unless
  `allow_private_ips: true` (this blocks SSRF to
  `169.254.169.254` and host-local services by default).
- Host pinning (always on): plain-HTTP requests are re-emitted
  with exactly one `Host` header built from the allowlisted
  request-line target (IDNA form; `:port` only when not 80), so
  a forged `Host: evil` never reaches the upstream (vhost
  confusion closed). `Proxy-Authorization` is stripped and
  never forwarded; `CONNECT` tunnels stay opaque by design.

Fail-closed in every direction: if the relay can't bind or can't
reach P1, the workload never starts; if the workload kills the
relay, its network access dies with it; when the workload exits,
the sandbox PID namespace (and the relay with it) is reaped.

Operational notes:

- P1 resolves names with the host resolver. `dns: off` refuses
  hostnames entirely — for fully pinned setups using literal-IP
  allowlist entries. Otherwise each name is resolved once and
  the IP set is pinned for `network.dns_pin_ttl` seconds
  (default 60): later requests reuse the pinned set without
  re-resolving, then the pin expires and the name is looked up
  fresh. This blocks the cheap DNS-rebinding flip; it does not
  stop an attacker who controls the first answer or who waits
  out the TTL — same as any DNS client. The guard order is
  untouched (private-IP guard sees the pinned set either way),
  and the pin map holds at most 512 hosts.
- If the host itself needs an upstream proxy (`$HTTPS_PROXY`),
  P1 chains through it. Unset it when testing against host-local
  servers (with `allow_private_ips: true`), or P1 will ask the
  corporate proxy for your `localhost`.
- The relay is a small Python script bind-mounted read-only at
  `/run/mantrap/relay.py`; the sandbox needs a `python3` (the
  default `init` template provides `/usr`). Every proxied
  request appends a `net.allow` / `net.deny` record to the audit
  log (`~/.mantrap/audit.log`, or `$MANTRAP_DATA_DIR/audit.log`).

## Approval gates

The mantrap interlock: like the physical mantrap's two doors,
the second door opens only on approval. A `gates:` policy block
lists rules; each rule matches one kind of action and decides it
**before** it happens:

```yaml
gates:
  - match: {exec.path: /usr/bin/curl}  # glob on the binary path
    action: ask
    description: "let the agent fetch with curl?"  # shown in the prompt
  - match: {net.domain: "*.internal"}  # case-insensitive glob
    action: deny
  - match: {fs.write: /data}          # absolute path prefix
    action: ask
```

Rules evaluate in policy order; **the first match wins**
(firewall order — put specific allows before broad asks). The
three match kinds:

- `exec.path`: glob against the binary (`fnmatch`); a bare
  command like `curl` also matches its `PATH` resolution, so a
  `/usr/bin/curl` glob catches `curl`. Checked before the
  sandbox starts.
- `net.domain`: case-insensitive glob on the request domain.
  Checked per request by the proxy; a deny surfaces as a 403 to
  the workload, never as a run failure.
- `fs.write`: absolute path prefix (`/data` matches `/data`
  and `/data/x`, not `/database`). Checked against the final
  mount list — including `exec --add-write` — before the
  sandbox starts.

`exec.path` and `fs.write` patterns are canonicalized (symlinks
resolved) on both the rule and the value side: a rule written as
`/usr/bin/curl` also matches `/bin/curl` on merged-`/usr`
systems, and `/host/../etc` cannot dodge an `fs.write: /etc`
rule. Canonicalization can only add matches, never remove them.

Actions: `allow` proceeds (audited), `deny` refuses fail-closed
with exit 2 (audited), `ask` pauses the workload and prompts on
the controlling terminal:

```
[mantrap] let the agent fetch with curl?: exec /usr/bin/curl — allow once / always / deny? [deny]
```

The workload's process group is SIGSTOP'd while the prompt is
up and SIGCONT'd after — the agent cannot race the operator's
answer. Answers: `once`/`o`, `always`/`a` (remembered for the
run), anything else denies. With no terminal, asks deny
fail-closed.

`--yes` denies every ask without prompting (for CI);
`--approve-all` allows every ask (still audited; prints a
warning on every run and is discouraged for anything
untrusted). Every decision — allow or deny — appends a
`gate.allow` / `gate.deny` record to the audit log with the
rule id and the decider (`rule`, `tty`, `tty-remembered`,
`flag --yes`, `flag --approve-all`, `no-tty`).

## Credential broker

Agent workloads need API keys and tokens, but a key baked into a
policy file or leaked into a log is a breach waiting to happen.
`secrets:` maps a NAME to where its value comes from — `env:VAR`
(mantrap's own environment), `file:PATH` (a 0600/0400 file; the
first line is the value), or `keyring:SERVICE/USER` (the login
keyring via `secretstorage`; best-effort, optional). The policy
carries only names and sources, never values.

The broker's guarantees:

- **Injected, not copied.** At run time each value is handed to
  the sandboxed process as an environment variable
  (`--setenv`), after the `env.allow` entries so secrets cannot
  be shadowed. Nothing about the secret touches the host
  filesystem.
- **Never in the audit log.** The recorded argv is a scrubbed
  copy — secret values are replaced with `***` before the
  record is written. This covers the case where the user's own
  shell expanded `$TOKEN` onto the workload's command line
  before mantrap ever saw it.
- **Never in error messages.** Resolution failures name the
  secret NAME and the source, never the value.
- **Fail-closed.** All secrets resolve before preflight runs;
  a missing variable, an unreadable file, a group-readable
  file, or an unreachable keyring aborts the run (exit 2)
  before the sandbox is created.
- **Inspectable.** `--dry-run` prints the resolved policy with
  values masked (`*** (N chars)`) and the exact bwrap command
  with secret values masked, executing nothing.

File sources must be mode 0600 or 0400; anything group- or
world-readable is refused outright.

## Tamper-evident audit log

Every record in `audit.log` carries `prev_hash` — the SHA-256 of
the previous record's canonical bytes — forming a hash chain back
to a genesis hash. Flip one byte in any record and the next
record's link breaks; `mantrap audit --verify` names the broken
record and exits 1. Records written before chaining existed
verify fine and are anchored by newer records chaining onto them.

Every 50 records, when a signing key exists (`mantrap keygen`),
mantrap appends a `sig` record: an Ed25519 signature over the
chain tip. The public keys live in the log itself (`key.gen` /
`key.rotate` records), so verification needs no private key and
survives key rotation. Verification re-checks every link and
every signature from the log alone.

One honest limitation: the chain anchors every record that has a
successor. The very last record is only anchored once the next
record — or the next periodic signature — commits to it. In other
words, tampering with the tip is detectable as soon as anything
else is appended.

## Snapshots and rollback

`mantrap snapshot` copies the policy's first writable mount with
`rsync -a --delete` into a timestamped directory plus a manifest
(path, size, SHA-256 per file; symlinks recorded by target).
`mantrap rollback <snap-id>` restores it — `--dry-run` first
shows exactly what would change — and then re-verifies the
restored tree against the manifest, so a corrupted snapshot fails
loudly instead of silently restoring the wrong files.

`run --snapshot` automates the safety net: a pre-run snapshot is
taken, and on a non-zero exit you get a rollback hint (or an
automatic, audit-logged restore with `--auto-rollback`). The
workload's exit code always propagates.

## Threat model (summary)

mantrap assumes the **workload is hostile** and the **policy
author is trusted** — a malicious policy is game over by design.
Namespaces, read-only mounts, the network proxy, seccomp, and
`RLIMIT_CORE=0` together keep a compromised workload away from
the host, its secrets, and other runs; the hash-chained,
signed audit log makes silent history rewrites detectable.

Known residual risks: the kernel is shared (a kernel 0-day breaks
the model — use a VM if that is in your threat model);
side-channels are not addressed; secrets in one sandbox are
visible to every process in that same sandbox (the sandbox is
the unit of trust); an allowlisted domain is a data-exfil channel
by definition; DNS rebinding is bounded by a per-name pin
(`dns_pin_ttl`, default 60s) but not eliminated — an attacker who
controls the first answer, or who waits out the TTL, can still
redirect to another public address. The
full analysis, including non-goals, is in
[`THREAT_MODEL.md`](THREAT_MODEL.md). EU AI Act mapping
(Art. 12 record-keeping, Art. 14 human oversight — guidance, not
legal advice) is in [`docs/EU_AI_ACT.md`](docs/EU_AI_ACT.md).

## Limitations

- **Linux only.** Other platforms get a clear error, not a
  degraded sandbox.
- **Process isolation, not a VM.** The kernel is shared; kernel
  exploits are out of scope. For hostile-tenant separation, use a
  VM or container runtime with a hardened kernel profile.
- **Secrets are visible in the host process table.** While a
  run executes, its secret values appear in the bwrap command
  line, visible via `ps` to the same user. This is the standard
  environment-variable caveat: the broker guarantees no secret
  on disk, in the audit log, or in error output — not invisibility
  from the owning user. The workload's own `/proc/<pid>/environ`
  lives inside the sandbox's PID namespace.

## FAQ

**Why not just use Docker?**
Docker isolates; mantrap *interlocks*. The difference is the
approval gates (a human must release the second door), the
deny-by-default policy with fail-closed preflight, and the
tamper-evident audit log. If you only need a container, use a
container.

**Why bubblewrap instead of writing my own namespaces?**
bwrap is a small, audited, setuid-root-free sandbox runner used
by Flatpak. Reimplementing namespace setup is where sandbox
escapes are born; mantrap composes bwrap with policy, proxy,
seccomp, gates, and audit instead.

**Does `network.mode: host` defeat the sandbox?**
It keeps the host network namespace — the workload can reach
the LAN and the internet directly. It is an explicit opt-in
(every run prints a stderr warning) for workloads that need raw
sockets; filesystem, seccomp, and process isolation still
apply. Prefer `allowlist`.

**Can the workload tell it is sandboxed?**
Yes — and that is fine. Hostname `mantrap`, missing devices,
no network: these are observable. mantrap is not a honeypot;
it is a cage.

**What happens if bwrap has a vulnerability?**
Same as any sandbox with a shared kernel: the model breaks.
Mitigations in depth — seccomp denylist, read-only mounts,
no-new-privs posture, and the audit log — raise the cost, but
track bwrap releases and update.

**How do I rotate the audit signing key?**
`mantrap keygen --rotate`. The old public key stays in the log
(`key.rotate` record), so old signatures verify forever. Keep
`signing.key` (0600) backed up; losing it does not invalidate
past signatures, but new `sig` records cannot be made.

**Can I run this in CI?**
Yes: `--yes` denies all `ask` gates without a terminal
(fail-closed), `--dry-run` validates policy without executing,
and `doctor` gates the environment. The no-`/proc` fallback
covers restricted CI containers.

## License

MIT.
