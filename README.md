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

network:
  mode: none           # none | host | allowlist
  allow_domains: []    # e.g. [pypi.org, "*.pythonhosted.org"]
  allow_plain_http: false  # plain http:// through the proxy; default deny
  allow_ports: [443]   # CONNECT targets restricted to these ports
  dns: host            # host | off (off: only literal-IP entries work)
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

Fail-closed in every direction: if the relay can't bind or can't
reach P1, the workload never starts; if the workload kills the
relay, its network access dies with it; when the workload exits,
the sandbox PID namespace (and the relay with it) is reaped.

Operational notes:

- P1 resolves names with the host resolver. `dns: off` refuses
  hostnames entirely — for fully pinned setups using literal-IP
  allowlist entries. DNS is re-resolved per request; names whose
  records change mid-session (rebinding) are checked against the
  records seen at request time only.
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

## License

MIT.
