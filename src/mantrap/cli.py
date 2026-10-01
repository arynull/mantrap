"""Command-line interface: init/run/exec/doctor/keygen/audit/snapshot."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, keys, snapshots
from .audit import (
    AuditError,
    append_record,
    append_run_record,
    iter_records,
    utc_now_iso,
    verify_log,
)
from .gates import GateDenied, GateError, GateSession
from .policy import (
    PolicyError,
    data_dir,
    load_policy,
    resolve_policy_path,
    validate_write_path,
)
from .sandbox import (
    SandboxError,
    build_bwrap_argv,
    find_bwrap,
    preflight,
    probe_userns,
    proc_available,
    run_workload,
)
from .secrets import (
    SecretsError,
    mask_argv,
    mask_value,
    resolve_secrets,
    scrub_argv,
)
from .snapshots import SnapshotError

INIT_TEMPLATE = """\
# mantrap.yaml — deny-by-default sandbox policy.
#
# Nothing is visible inside the sandbox unless it is listed here:
# filesystem paths (fs.read / fs.write), environment variables
# (env.allow), secrets (secrets), and network egress (network.mode).
# The default is deny-by-default: no network, no secrets.
#
# Policy resolution order: --policy FILE, then ./mantrap.yaml,
# then ~/.mantrap/mantrap.yaml (or $MANTRAP_DATA_DIR/mantrap.yaml).

fs:
  # Read-only mounts. /usr, /bin, /lib, /lib64 carry the toolchain
  # (python, shell, shared libraries) — without them almost nothing
  # runs inside the sandbox.
  read:
    - /usr
    - /bin
    - /lib
    - /lib64
  # Writable mounts. Uncomment and create the directory to give the
  # workload a workspace (absolute path required; relative paths
  # are rejected). The first entry becomes the working
  # directory inside the sandbox.
  write:
    # - ./workspace

env:
  # Environment variables copied from the caller into the sandbox.
  # No wildcards: list each name explicitly. A listed name that is
  # missing from the caller's environment is a fail-closed error.
  allow: []

limits:
  # Wall-clock timeout in seconds: SIGTERM, 5s grace, then SIGKILL
  # to the whole process group. Exit code 124 marks a limit kill.
  timeout: 300
  # Optional: uncomment to enforce via prlimit(1).
  # memory: 1073741824      # RLIMIT_AS in bytes
  # cpu_seconds: 60         # RLIMIT_CPU in seconds
  # nproc: 64               # RLIMIT_NPROC

#secrets:
  # Credential broker: NAME -> source. The VALUE never appears in
  # this file, the audit log, or error messages. Injected into the
  # sandbox as an environment variable (--setenv) only.
  # GH_TOKEN: {env: GH_TOKEN}              # from mantrap's own env
  # API_KEY: {file: /home/user/.secrets/api_key}  # 0600 file, 1st line
  # DB_PASS: {keyring: myservice/dbuser}   # needs 'secretstorage'

#network:
  # Egress control. none (default): --unshare-net, no route out.
  # host: keep the host network namespace (stderr warning every run).
  # allowlist: filtered egress via a host-side proxy; see README.
  # mode: none
  # allow_domains: [pypi.org, "*.pythonhosted.org"]
  # allow_plain_http: false
  # allow_ports: [443]
  # dns: host
  # dns_pin_ttl: 60        # seconds a resolved name stays pinned to
  #                        # its IP set (anti-DNS-rebinding); 0 disables
  # allow_private_ips: false

#gates:
  # Approval gates: the mantrap interlock. Rules evaluate in order;
  # the first match wins (firewall order — put specific allows before
  # broad asks). Every decision is written to the audit log.
  #   - match: {exec.path: /usr/bin/curl}   # glob on the binary
  #     action: ask                         # allow | deny | ask
  #   - match: {net.domain: "*.internal"}   # case-insensitive glob
  #     action: deny
  #   - match: {fs.write: /data}            # absolute path prefix
  #     action: ask
  # ask pauses the workload and prompts on the controlling terminal;
  # --yes denies every ask (CI), --approve-all allows every ask
  # (logged; discouraged — prints a warning on every run).
"""


def cmd_init(force: bool) -> int:
    """Scaffold ./mantrap.yaml. Returns the process exit code."""
    target = Path.cwd() / "mantrap.yaml"
    if target.exists() and not force:
        print(
            f"error: {target} already exists; "
            "pass --force to overwrite it",
            file=sys.stderr,
        )
        return 1
    target.write_text(INIT_TEMPLATE, encoding="utf-8")
    print(f"wrote {target}")
    return 0


def cmd_run(
    policy_file: str | None,
    workload: list[str],
    dry_run: bool = False,
    *,
    yes: bool = False,
    approve_all: bool = False,
    add_writes: list[str] | None = None,
    command_name: str = "run",
    snapshot: bool = False,
    auto_rollback: bool = False,
) -> int:
    """Run a workload in the sandbox. Returns the exit code."""
    if not workload:
        print(
            "error: no command given; "
            f"usage: mantrap {command_name} -- <cmd> [args...]",
            file=sys.stderr,
        )
        return 2
    if yes and approve_all:
        print(
            "error: --yes and --approve-all are mutually exclusive",
            file=sys.stderr,
        )
        return 2
    try:
        policy_path = resolve_policy_path(policy_file)
        policy, digest = load_policy(policy_path)
        # Fail-closed: resolve before preflight/bwrap so nothing
        # starts with a partially-resolved secret set.
        secrets = resolve_secrets(policy.secrets)
        for raw in add_writes or []:
            # Same validation as fs.write; appended for this run
            # only, never written back to the policy file.
            policy.fs_write.append(
                validate_write_path(raw, "fs.write (--add-write)")
            )
    except (PolicyError, SandboxError, SecretsError, GateError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if dry_run:
        return _cmd_dry_run(policy_path, policy, workload, secrets)
    if auto_rollback:
        snapshot = True  # rolling back needs a pre-run snapshot
    snap_meta = None
    if snapshot:
        try:
            workspace = _run_workspace(policy, digest)
            snap_meta = snapshots.create_snapshot(
                workspace,
                data_dir=data_dir(),
                policy_sha256=digest,
                message="pre-run auto-snapshot",
            )
            append_record(
                {
                    "ts": utc_now_iso(),
                    "type": "snapshot.create",
                    "snap_id": snap_meta.snap_id,
                    "workspace": str(workspace),
                    "message": "pre-run auto-snapshot",
                    "files": snap_meta.files,
                }
            )
            print(
                f"mantrap: snapshotted workspace -> {snap_meta.snap_id}",
                file=sys.stderr,
            )
        except (PolicyError, SnapshotError, AuditError, OSError) as exc:
            print(f"error: cannot snapshot workspace: {exc}", file=sys.stderr)
            return 2
    if approve_all:
        print(
            "mantrap: --approve-all allows every approval gate "
            "without prompting; every decision is still audited",
            file=sys.stderr,
        )
    gate_session = GateSession(
        policy.gates,
        auto_yes=yes,
        approve_all=approve_all,
        audit_append=append_record,
    )
    try:
        bwrap = preflight()
        code, killed, duration, fallback = run_workload(
            bwrap, policy, workload, secrets=secrets,
            gate_session=gate_session,
        )
    except GateDenied as exc:
        print(
            f"error: denied by {exc.rule_id}: {exc.detail}",
            file=sys.stderr,
        )
        return 2
    except (PolicyError, SandboxError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        append_run_record(
            policy_sha256=digest,
            # Scrubbed copy: the workload gets the real argv, but a
            # secret the user's shell expanded onto the command line
            # must not reach the audit log.
            argv=scrub_argv(workload, secrets),
            exit_code=code,
            duration_s=duration,
            killed_by_limit=killed,
            proc_fallback=fallback,
        )
    except OSError as exc:
        print(
            f"error: cannot write audit log ({exc}); "
            "refusing to treat the run as complete",
            file=sys.stderr,
        )
        return 2
    if killed:
        print(
            f"mantrap: workload killed after {policy.timeout}s limit "
            "(exit 124)",
            file=sys.stderr,
        )
    if snap_meta is not None and (killed or code != 0):
        if auto_rollback:
            try:
                restored = snapshots.rollback(snap_meta)
                append_record(
                    {
                        "ts": utc_now_iso(),
                        "type": "snapshot.rollback",
                        "snap_id": snap_meta.snap_id,
                        "workspace": snap_meta.workspace,
                        "restored_files": len(restored),
                        "auto": True,
                    }
                )
                print(
                    f"mantrap: run failed; workspace rolled back to "
                    f"{snap_meta.snap_id} ({len(restored)} files)",
                    file=sys.stderr,
                )
            except (SnapshotError, AuditError, OSError) as exc:
                print(
                    f"mantrap: run failed AND auto-rollback failed ({exc}); "
                    f"snapshot {snap_meta.snap_id} retained for a manual "
                    "rollback",
                    file=sys.stderr,
                )
        else:
            print(
                f"mantrap: run failed; workspace snapshot retained as "
                f"{snap_meta.snap_id} — restore with "
                f"`mantrap rollback {snap_meta.snap_id}`",
                file=sys.stderr,
            )
    return code


def _cmd_dry_run(policy_path, policy, workload, secrets) -> int:
    """Print the resolved policy (masked) and the bwrap command.

    Nothing is executed, no audit record is written, the proxy is
    not started. Secret values never appear in the output.
    """
    print(f"# mantrap dry-run: {policy_path}")
    print("# secrets (values masked):")
    print("secrets:")
    if secrets:
        for name in sorted(secrets):
            print(f"  {name}: {mask_value(secrets[name])}")
    else:
        print("  {}")
    preview = build_bwrap_argv(
        "bwrap", policy, workload, with_proc=True, secrets=secrets
    )
    print("# bwrap command (secret values masked):")
    print(shlex.join(mask_argv(preview, set(secrets))))
    print("gates:")
    if policy.gates:
        for rule in policy.gates:
            print(
                f"  {rule.id}: {rule.match_kind} {rule.pattern}"
                f" -> {rule.action}"
            )
    else:
        print("  {}")
    return 0


def cmd_keygen(*, rotate: bool = False) -> int:
    """Create (or rotate) the Ed25519 audit-log signing key."""
    directory = data_dir()

    def _audit(record: dict) -> dict:
        return append_record(record, directory=directory)

    try:
        if rotate:
            new_key_id, _new_pub, old_key_id = keys.rotate(
                directory, audit_append=_audit
            )
            print(f"rotated signing key: {old_key_id} -> {new_key_id}")
        else:
            key_id, _pub = keys.generate(directory, audit_append=_audit)
            print(f"signing key created: {key_id}")
            print("every 50 audit records are now signed with this key;")
            print("verify any time with: mantrap audit --verify")
    except (keys.KeyError, AuditError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _format_record(record: dict) -> str:
    ts = record.get("ts", "?")
    rtype = record.get("type", "?")
    detail = ""
    if rtype == "run":
        detail = (
            f"exit={record.get('exit_code')} "
            f"dur={record.get('duration_s', 0):.1f}s "
            f"policy={str(record.get('policy_sha256', ''))[:12]}"
        )
    elif rtype in ("net.allow", "net.deny"):
        detail = (
            f"{record.get('scheme', '')}://{record.get('domain', '')}"
            f":{record.get('port', '')} {record.get('reason', '')}"
        )
    elif rtype in ("gate.allow", "gate.deny"):
        detail = (
            f"{record.get('rule', '')} {record.get('detail', '')} "
            f"({record.get('decider', '')})"
        )
    elif rtype == "sig":
        detail = (
            f"key={record.get('key_id', '')} "
            f"tip={str(record.get('tip_hash', ''))[:12]}…"
        )
    elif rtype in ("key.gen", "key.rotate"):
        detail = f"key_id={record.get('key_id', '')}"
        if rtype == "key.rotate":
            detail += f" prev={record.get('prev_key_id', '')}"
    elif rtype == "snapshot.create":
        detail = f"{record.get('snap_id', '')} {record.get('message', '')}".strip()
    elif rtype == "snapshot.rollback":
        detail = (
            f"{record.get('snap_id', '')} "
            f"restored={record.get('restored_files', '?')}"
        )
    else:
        rest = {k: v for k, v in record.items()
                if k not in ("v", "ts", "type", "prev_hash")}
        detail = " ".join(f"{k}={v}" for k, v in list(rest.items())[:4])
    return f"{ts}  {rtype:16} {detail}".rstrip()


def _parse_since(raw: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError(
            f"--since must be an ISO-8601 timestamp, got {raw!r}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def cmd_audit(
    *, verify: bool = False, since: str | None = None,
    as_json: bool = False,
) -> int:
    """Show the audit log; --verify re-checks chain + signatures."""
    if verify:
        result = verify_log()
        if result.ok:
            print(
                f"audit log verified: {result.records} records, "
                f"{result.signatures} signatures, chain intact"
            )
            return 0
        print(f"audit verification FAILED: {result.error}", file=sys.stderr)
        return 1
    try:
        records = list(iter_records())
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if since is not None:
        try:
            cutoff = _parse_since(since)
        except PolicyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        records = [
            (n, r) for n, r in records
            if datetime.fromisoformat(r["ts"]) >= cutoff
        ]
    if as_json:
        for _n, record in records:
            print(json.dumps(record, sort_keys=True))
    else:
        for _n, record in records:
            print(_format_record(record))
    return 0


def _run_workspace(policy, digest: str) -> Path:
    if not policy.fs_write:
        raise PolicyError(
            "snapshots need a writable workspace: add an fs.write "
            "mount (or use `exec --add-write PATH`)"
        )
    return Path(policy.fs_write[0])


def cmd_snapshot(
    policy_file: str | None, message: str | None = None
) -> int:
    """Snapshot the policy's first writable mount (host-side)."""
    try:
        policy_path = resolve_policy_path(policy_file)
        policy, digest = load_policy(policy_path)
        workspace = _run_workspace(policy, digest)
        meta = snapshots.create_snapshot(
            workspace,
            data_dir=data_dir(),
            policy_sha256=digest,
            message=message,
        )
        append_record(
            {
                "ts": utc_now_iso(),
                "type": "snapshot.create",
                "snap_id": meta.snap_id,
                "workspace": str(workspace),
                "message": message or "",
                "files": meta.files,
            }
        )
    except (PolicyError, SnapshotError, AuditError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"snapshot {meta.snap_id} ({meta.files} files)")
    return 0


def cmd_snapshots(*, as_json: bool = False) -> int:
    """List snapshots, newest first."""
    metas = snapshots.list_snapshots(data_dir())
    if as_json:
        for meta in metas:
            print(json.dumps({
                "snap_id": meta.snap_id,
                "ts": meta.ts_iso,
                "message": meta.message,
                "workspace": meta.workspace,
                "files": meta.files,
            }, sort_keys=True))
    else:
        for meta in metas:
            msg = f" — {meta.message}" if meta.message else ""
            print(f"{meta.snap_id}  {meta.ts_iso}  {meta.files} files{msg}")
    return 0


def cmd_rollback(snap_id: str, *, dry_run: bool = False) -> int:
    """Restore a snapshot (--dry-run shows the diff first)."""
    try:
        meta = snapshots.find_snapshot(data_dir(), snap_id)
        diffs = snapshots.rollback(meta, dry_run=dry_run)
    except (SnapshotError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if dry_run:
        if not diffs:
            print(f"{meta.snap_id}: workspace already matches the snapshot")
        for diff in diffs:
            print(f"{diff.change:8} {diff.path}")
        return 0
    try:
        append_record(
            {
                "ts": utc_now_iso(),
                "type": "snapshot.rollback",
                "snap_id": meta.snap_id,
                "workspace": meta.workspace,
                "restored_files": len(diffs),
                "auto": False,
            }
        )
    except (AuditError, OSError) as exc:
        print(f"error: cannot write audit log ({exc})", file=sys.stderr)
        return 2
    print(f"rolled back {meta.snap_id} ({len(diffs)} files restored)")
    return 0


def _check(label: str, status: str, hint: str = "") -> bool:
    """Print one doctor line; returns True when it is not FAIL."""
    line = f"{status:4}  {label}"
    if hint:
        line += f" — {hint}"
    print(line)
    return status != "FAIL"


def cmd_doctor() -> int:
    """Run environment checks. Exit 0 iff no FAIL."""
    ok = True

    bwrap = None
    try:
        bwrap = find_bwrap()
        ok &= _check("bwrap on PATH", "PASS", f"found {bwrap}")
    except SandboxError:
        ok &= _check(
            "bwrap on PATH", "FAIL", "install bubblewrap "
            "(e.g. `apt install bubblewrap`)"
        )

    if bwrap is not None and probe_userns(bwrap, with_proc=False):
        ok &= _check("user namespaces usable", "PASS", "bwrap probe ran")
    else:
        ok &= _check(
            "user namespaces usable",
            "FAIL",
            "enable unprivileged user namespaces "
            "(e.g. `sysctl kernel.unprivileged_userns_clone=1`)",
        )

    if bwrap is not None and proc_available(bwrap):
        ok &= _check("private /proc mountable", "PASS", "")
    else:
        ok &= _check(
            "private /proc mountable",
            "WARN",
            "no-proc fallback will run workloads without /proc "
            "(isolation unaffected)",
        )

    directory = data_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".writetest"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        ok &= _check("audit dir writable", "PASS", f"{directory}")
    except OSError as exc:
        ok &= _check(
            "audit dir writable",
            "FAIL",
            f"cannot write {directory}: {exc}",
        )

    return 0 if ok else 1


def _add_run_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", default=None,
                        help="policy file (default: resolution order)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the resolved policy (secrets masked) "
                             "and the bwrap command without running anything")
    parser.add_argument(
        "--yes", action="store_true",
        help="deny every approval-gate ask without prompting "
             "(for CI; fail-closed)",
    )
    parser.add_argument(
        "--approve-all", action="store_true",
        help="allow every approval-gate ask without prompting "
             "(logged; discouraged)",
    )
    parser.add_argument(
        "--snapshot", action="store_true",
        help="snapshot the first fs.write workspace before the run "
             "(ignored with --dry-run)",
    )
    parser.add_argument(
        "--auto-rollback", action="store_true",
        help="restore the pre-run snapshot when the workload exits "
             "non-zero (implies --snapshot; the restore is audited)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mantrap",
        description="Run untrusted commands in a bubblewrap sandbox.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="scaffold ./mantrap.yaml")
    p_init.add_argument(
        "--force", action="store_true",
        help="overwrite an existing mantrap.yaml",
    )

    p_run = sub.add_parser("run", help="run a command in the sandbox")
    _add_run_flags(p_run)
    p_run.add_argument(
        "workload", nargs=argparse.REMAINDER,
        help="command after --, e.g. mantrap run -- id -u",
    )

    p_exec = sub.add_parser(
        "exec",
        help="run a command in the sandbox with extra write mounts",
    )
    _add_run_flags(p_exec)
    p_exec.add_argument(
        "--add-write", action="append", default=None, metavar="PATH",
        help="grant the workload a writable mount for this run only "
             "(repeatable; validated like fs.write)",
    )
    p_exec.add_argument(
        "workload", nargs=argparse.REMAINDER,
        help="command after --, e.g. mantrap exec "
             "--add-write /home/user/out -- make build",
    )

    sub.add_parser("doctor", help="check the sandbox environment")

    p_keygen = sub.add_parser(
        "keygen", help="create the audit-log signing key")
    p_keygen.add_argument(
        "--rotate", action="store_true",
        help="replace the existing key (old signatures stay verifiable)",
    )

    p_audit = sub.add_parser("audit", help="show the audit log")
    p_audit.add_argument(
        "--verify", action="store_true",
        help="re-check the hash chain and every signature; "
             "exit 1 naming the first broken record",
    )
    p_audit.add_argument(
        "--since", default=None, metavar="TS",
        help="only show records at or after this ISO-8601 timestamp",
    )
    p_audit.add_argument(
        "--json", action="store_true",
        help="print records as JSON (one per line)",
    )

    p_snapshot = sub.add_parser(
        "snapshot", help="snapshot the policy's writable workspace")
    p_snapshot.add_argument("--policy", default=None,
                            help="policy file (default: resolution order)")
    p_snapshot.add_argument(
        "--message", default=None,
        help="label stored with the snapshot",
    )

    p_snapshots = sub.add_parser("snapshots", help="list snapshots")
    p_snapshots.add_argument(
        "--json", action="store_true",
        help="print snapshots as JSON (one per line)",
    )

    p_rollback = sub.add_parser(
        "rollback", help="restore the workspace from a snapshot")
    p_rollback.add_argument("snap_id", help="snapshot id from `snapshots`")
    p_rollback.add_argument(
        "--dry-run", action="store_true",
        help="show what would change without restoring anything",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "init":
        return cmd_init(args.force)
    if args.command in ("run", "exec"):
        workload = list(args.workload or [])
        # argparse REMAINDER keeps the leading "--" when present;
        # drop exactly one so `run -- id` works and `run id` does too.
        if workload and workload[0] == "--":
            workload = workload[1:]
        if not workload and "--" not in (argv or sys.argv[1:]):
            print(
                "error: no command given; "
                f"usage: mantrap {args.command} -- <cmd> [args...]",
                file=sys.stderr,
            )
            return 2
        return cmd_run(
            args.policy,
            workload,
            dry_run=args.dry_run,
            yes=args.yes,
            approve_all=args.approve_all,
            add_writes=args.add_write
            if args.command == "exec" else None,
            command_name=args.command,
            snapshot=args.snapshot,
            auto_rollback=args.auto_rollback,
        )
    if args.command == "doctor":
        return cmd_doctor()
    if args.command == "keygen":
        return cmd_keygen(rotate=args.rotate)
    if args.command == "audit":
        return cmd_audit(
            verify=args.verify, since=args.since, as_json=args.json
        )
    if args.command == "snapshot":
        return cmd_snapshot(args.policy, message=args.message)
    if args.command == "snapshots":
        return cmd_snapshots(as_json=args.json)
    if args.command == "rollback":
        return cmd_rollback(args.snap_id, dry_run=args.dry_run)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
