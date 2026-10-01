# EU AI Act alignment

> Guidance, not legal advice. The EU AI Act (Regulation (EU)
> 2024/1689) obligations depend on your role (provider, deployer),
> your system's risk classification, and your member-state
> implementation. This document maps mantrap's technical features
> to two articles enterprise users ask about; it does not certify
> compliance.

## Article 12 — Record-keeping

> "High-risk AI systems shall be designed and developed with
> capabilities enabling the automatic recording of events
> ('logs')..."

What mantrap provides:

- **Every run is logged.** `mantrap run` / `exec` append one
  `run` record per execution (policy digest, workload argv,
  exit code, duration, killed-by-limit) plus `net.allow` /
  `net.deny` records for each egress decision and `gate.allow` /
  `gate.deny` records for approval-gate decisions.
- **Tamper-evidence.** Each record carries `prev_hash`, the
  SHA-256 of the previous record's canonical bytes, chained back
  to a genesis hash; every 50 records a `sig` record carries an
  Ed25519 signature over the chain tip. `mantrap audit --verify`
  re-checks every link and signature and names the first broken
  record. Deleting or editing history is detectable.
- **Key lifecycle in the log.** `mantrap keygen` / `keygen
  --rotate` publish `key.gen` / `key.rotate` records containing
  the public keys, so signatures remain verifiable after rotation
  and the rotation itself is auditable.
- **Retention is yours.** The log lives at
  `~/.mantrap/audit.log` (or `MANTRAP_DATA_DIR`); retention,
  backup, and archival policy are the operator's — mantrap does
  not silently rotate or prune.

What mantrap does **not** do: decide what is "appropriate" to log
for your risk assessment, set retention periods, or store logs
off-box. Pair it with your log pipeline.

## Article 14 — Human oversight

> "High-risk AI systems shall be designed and developed in such a
> way... that they can be effectively overseen by natural persons."

What mantrap provides:

- **Approval gates (the interlock).** Policy rules can require a
  human decision before the workload executes a matching program
  (`exec.path`), writes to a matching path (`fs.write`), or
  contacts a matching domain (`net.domain`). On `ask`, the
  workload's process group is stopped (`SIGSTOP`) and a prompt
  goes to the operator's terminal; `once`/`always`/`deny` are the
  answers, each audit-logged with the decider. A denied gate
  never runs.
- **Oversight is enforced, not advisory.** Gates are evaluated in
  the enforcement path (bwrap argv construction, proxy request
  handling) — the workload cannot bypass them by being clever,
  only the human (or an `allow` rule) can release them.
- **Kill switch.** `limits.timeout` bounds every run; Ctrl-C /
  timeout kills the whole process group (`SIGTERM`, then
  `SIGKILL` after a grace period). `--auto-rollback` additionally
  restores the workspace snapshot on failure.

What mantrap does **not** do: define who in your organization
holds the oversight role, or guarantee the human pays attention.
An `allow` rule is a deliberate delegation — review gate rules
like firewall rules.

## Suggested control mapping (starting point)

| Obligation | mantrap feature | Operator duty |
|---|---|---|
| Art. 12 logging | hash-chained signed audit log | ship `audit.log` to immutable storage; set retention |
| Art. 12 traceability | policy digest per `run` record | version-control policies alongside the log |
| Art. 14 oversight | approval gates (`ask`) | staff the terminal; review `allow` rules |
| Art. 14 intervention | timeout + process-group kill | set timeouts per risk; test the kill path |

## Known limits for this mapping

- The audit log proves *what the sandbox saw*. It cannot prove
  what happened inside a workload that exfiltrated via an
  allowlisted domain (see `THREAT_MODEL.md`: allowlists are trust
  decisions).
- `audit --verify` detects tampering; it does not prevent it.
  Verification must run on a schedule, on a copy the workload
  cannot reach.
