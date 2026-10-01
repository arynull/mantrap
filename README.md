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

network:
  mode: none           # none | host | allowlist
  allow_domains: []    # e.g. [pypi.org, "*.pythonhosted.org"]
  allow_plain_http: false  # plain http:// through the proxy; default deny
  allow_ports: [443]   # CONNECT targets restricted to these ports
  dns: host            # host | off (off: only literal-IP entries work)
  allow_private_ips: false  # default deny: blocks SSRF to 127.0.0.0/8,
                           # 10/8, 169.254.169.254, ...
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

## Limitations

- **Linux only.** Other platforms get a clear error, not a
  degraded sandbox.
- **Process isolation, not a VM.** The kernel is shared; kernel
  exploits are out of scope. For hostile-tenant separation, use a
  VM or container runtime with a hardened kernel profile.
- Secrets handling is limited to `env.allow` passthrough; a
  proper credential broker is on the roadmap (v0.3).

## License

MIT.
