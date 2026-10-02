"""Tamper-evident audit log: one JSON object per line.

v2 schema (this version): every record carries ``prev_hash`` — the
SHA-256 of the previous record's canonical bytes — forming a hash
chain back to a genesis hash. Every ``SIG_INTERVAL`` records, when a
signing key exists (``mantrap keygen``), a ``sig`` record is appended
with an Ed25519 signature over the chain tip.

Forward compatibility: v0.1 records have no ``prev_hash``. They
verify fine (the link check is skipped for them) and newer records
chain onto them, anchoring the old history.

Verification (``mantrap audit --verify``) recomputes every link and
every signature from the log alone: public keys come from the
``key.gen`` / ``key.rotate`` records in the log, so no private key
is needed. Any flipped byte breaks the chain at the next record
and is reported with the record number.

Verify-on-start (``verify_tip``, run by every ``run``/``exec``):
a bounded, fail-closed preflight over the tail of the log. It walks
every ``prev_hash`` link from the most recent ``sig`` record to the
tip, re-checks that signature, and cross-checks the tip against the
``audit.tip`` sentinel written on every append. Cost is
O(SIG_INTERVAL) on a signing box, a full ``verify_log`` when no
signature exists yet. What it deliberately does NOT do is re-walk
history older than the last signature — that is what the manual
``mantrap audit --verify`` is for.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import _ed25519
from . import keys as signing_keys
from .policy import data_dir

AUDIT_FILENAME = "audit.log"
GENESIS_HASH = "0" * 64
SIG_INTERVAL = 50
# Deletion/truncation guard: the last known tip + record count,
# written next to the log (0600). Derived state — always behind the
# log, never ahead of it.
TIP_FILENAME = "audit.tip"
TIP_MODE = 0o600


class AuditError(Exception):
    """The audit log is unreadable or failed verification."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_bytes(record: dict) -> bytes:
    """Deterministic serialization used for hashing and signing."""
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def record_hash(record: dict) -> str:
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def _read_lines(target: Path) -> list[str]:
    if not target.exists():
        return []
    return target.read_text(encoding="utf-8").splitlines(keepends=True)


def _atomic_write_lines(target: Path, lines: list[str]) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix="audit.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _append_signature(target_dir: Path, tip_hash: str) -> dict:
    """Append a `sig` record over the chain tip. Fail-closed on keys."""
    seed, key_id = signing_keys.load_seed(target_dir)
    signature = _ed25519.sign(seed, bytes.fromhex(tip_hash))
    record = {
        "v": 2,
        "ts": utc_now_iso(),
        "type": "sig",
        "key_id": key_id,
        "tip_hash": tip_hash,
        "signature": signature.hex(),
        "prev_hash": tip_hash,
    }
    target = target_dir / AUDIT_FILENAME
    lines = _read_lines(target)
    # The tip must still be the tip: refuse to sign over a concurrently
    # appended record rather than produce a misleading signature.
    if not lines or record_hash(json.loads(lines[-1])) != tip_hash:
        raise AuditError("audit log changed during signing; retry the command")
    lines.append(json.dumps(record) + "\n")
    _atomic_write_lines(target, lines)
    return record


def tip_path(directory: Path) -> Path:
    """Path of the tip sentinel for a data directory."""
    return directory / TIP_FILENAME


def _write_tip(target_dir: Path, tip_hash: str, records: int) -> None:
    """Persist the tip sentinel (0600): deletion/truncation guard.

    ORDER — the log line is already durable when this runs, and
    that is the direction that is safe. A sentinel that LAGS the log
    (a crash right here) is the recoverable case: the next append
    rewrites it, and verify_tip accepts a log longer than the
    sentinel by re-anchoring the sentinel's own hash against the
    chain at its recorded position. The opposite order would leave
    the sentinel claiming records the log does not have, which
    verify_tip must read as deletion — so a crash would be
    indistinguishable from tampering and would block every later
    run. Never the reverse.

    A failed checkpoint raises AuditError: refusing to continue is
    better than leaving the next start unable to tell a truncate
    from an ordinary append.
    """
    path = tip_path(target_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"tip_hash": tip_hash, "records": records}, sort_keys=True
    ) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix="audit.tip.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, TIP_MODE)
        os.replace(tmp_name, path)
        os.chmod(path, TIP_MODE)
    except OSError as exc:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise AuditError(
            f"cannot write audit tip sentinel {path}: {exc}"
        ) from exc


def _read_tip(target_dir: Path) -> dict | None:
    """The sentinel dict, or None when absent (pre-v1.2.0 logs)."""
    path = tip_path(target_dir)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuditError(
            f"audit tip sentinel {path} is unreadable: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise AuditError(
            f"audit tip sentinel {path} is not a JSON object"
        )
    return data


def append_record(record: dict, directory: Path | None = None) -> dict:
    """Atomically append one JSON record to the audit log.

    The record is chained (``v`` normalized to 2, ``prev_hash``
    added) and every ``SIG_INTERVAL`` records a ``sig`` record is
    appended when a signing key exists. The tip sentinel is refreshed
    afterwards (see _write_tip for why that order). Raises
    OSError/AuditError when the record cannot be persisted (callers
    treat that as fail-closed).
    """
    target_dir = directory if directory is not None else data_dir()
    target = target_dir / AUDIT_FILENAME
    chained = dict(record)
    chained["v"] = 2
    lines = _read_lines(target)
    if lines:
        chained["prev_hash"] = record_hash(json.loads(lines[-1]))
    else:
        chained["prev_hash"] = GENESIS_HASH
    lines.append(json.dumps(chained) + "\n")
    _atomic_write_lines(target, lines)
    record_count = len(lines)
    tip = record_hash(chained)
    if record_count % SIG_INTERVAL == 0 and signing_keys.has_key(target_dir):
        signed = _append_signature(target_dir, tip)
        record_count += 1
        tip = record_hash(signed)
    _write_tip(target_dir, tip, record_count)
    return chained


def append_run_record(
    *,
    policy_sha256: str,
    argv: list[str],
    exit_code: int,
    duration_s: float,
    killed_by_limit: bool,
    proc_fallback: bool,
):
    """Append one run record; returns the record dict.

    Raises OSError when the record cannot be persisted. Callers treat
    that as fail-closed: an unrunnable audit trail means nothing runs.
    """
    record = {
        "v": 1,  # normalized to 2 by append_record
        "ts": utc_now_iso(),
        "type": "run",
        "policy_sha256": policy_sha256,
        "argv": list(argv),
        "uid": os.getuid(),
        "exit_code": exit_code,
        "duration_s": duration_s,
        "killed_by_limit": killed_by_limit,
        "proc_fallback": proc_fallback,
    }
    return append_record(record)


def iter_records(directory: Path | None = None):
    """Yield (line_number, record) for every record in the log."""
    target_dir = directory if directory is not None else data_dir()
    target = target_dir / AUDIT_FILENAME
    if not target.exists():
        return
    for lineno, line in enumerate(
        target.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditError(
                f"record #{lineno}: not valid JSON ({exc})"
            ) from exc
        if not isinstance(record, dict):
            raise AuditError(f"record #{lineno}: not a JSON object")
        yield lineno, record


@dataclass
class VerifyResult:
    ok: bool
    records: int
    signatures: int
    error: str | None = None


def apply_key_record(
    keyring: dict[str, bytes], record: dict, lineno: int
) -> str | None:
    """Fold one key.gen/key.rotate record into ``keyring``.

    Returns None when the record is well-formed, else the error
    text (the same wording ``verify_log`` reports). Shared with the
    keyring bootstrap in keys.py so the trust rules for key records
    exist exactly once.
    """
    rtype = record.get("type", "?")
    key_id = record.get("key_id")
    pub_hex = record.get("public_key")
    if not isinstance(pub_hex, str):
        return f"record #{lineno} ({rtype}): malformed public_key"
    try:
        pub = bytes.fromhex(pub_hex)
    except ValueError:
        return f"record #{lineno} ({rtype}): malformed public_key"
    if len(pub) != 32 or not key_id:
        return f"record #{lineno} ({rtype}): malformed key record"
    if rtype == "key.rotate":
        prev_key_id = record.get("prev_key_id")
        if keyring and prev_key_id not in keyring:
            return (
                f"record #{lineno} (key.rotate): prev_key_id "
                f"{prev_key_id!r} is not a known key — the key "
                f"history was modified"
            )
    keyring[key_id] = pub
    return None


def check_signature(
    keyring: dict[str, bytes],
    record: dict,
    lineno: int,
    prev_record: dict | None,
    prev_lineno: int,
) -> str | None:
    """Validate one ``sig`` record; returns the error text or None.

    Shared by ``verify_log`` (every signature) and ``verify_tip``
    (the most recent one), so the trust rules for a signature exist
    exactly once.
    """
    key_id = record.get("key_id")
    if key_id not in keyring:
        return (
            f"record #{lineno} (sig): unknown key_id "
            f"{key_id!r} — the key history was modified"
        )
    tip_hex = record.get("tip_hash")
    sig_hex = record.get("signature")
    if not isinstance(tip_hex, str) or not isinstance(sig_hex, str):
        return f"record #{lineno} (sig): malformed tip_hash/signature"
    try:
        tip = bytes.fromhex(tip_hex)
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return f"record #{lineno} (sig): malformed tip_hash/signature"
    if prev_record is None or record.get("tip_hash") != record_hash(
        prev_record
    ):
        return (
            f"record #{lineno} (sig): tip_hash does not match "
            f"record #{prev_lineno} — the log was modified"
        )
    if not _ed25519.verify(keyring[key_id], tip, sig):
        return (
            f"record #{lineno} (sig): bad Ed25519 signature "
            f"(key {key_id})"
        )
    return None


def verify_tip(directory: Path | None = None) -> VerifyResult:
    """Fail-closed preflight over the log, run before every start.

    Called by ``run``/``exec`` before secrets, snapshot, gates,
    proxy or bwrap: a modified history must not be appended to and
    must not be able to keep running.

    As strong as ``verify_log`` against modification, at lower
    cost. Every ``prev_hash`` link is walked — one SHA-256 per
    record, so the pass is O(number of records) but cheap per
    record — while only the most recent ``sig`` record's Ed25519
    signature is re-checked (the expensive operation ``verify_log``
    repeats every 50 records). The transitive argument: that
    signature authenticates the hash of the record preceding it,
    and the links walked from there back to genesis cover every
    earlier record, so a flipped byte anywhere breaks a link
    without needing every signature re-verified.

    With no ``sig`` record yet there is no anchor to trust, so the
    whole log is verified. Deletion/truncation is caught by the
    ``audit.tip`` sentinel: a missing log that still has a sentinel,
    or a log shorter than the sentinel, fails closed. A missing or
    empty log with no sentinel is a fresh install and passes
    (v0.1 forward compatibility).
    """
    target_dir = directory if directory is not None else data_dir()
    try:
        tip = _read_tip(target_dir)
    except AuditError as exc:
        return VerifyResult(
            ok=False, records=0, signatures=0, error=str(exc)
        )

    try:
        records = list(iter_records(target_dir))
    except AuditError as exc:
        return VerifyResult(
            ok=False, records=0, signatures=0, error=str(exc)
        )

    if not records:
        if tip is not None:
            return VerifyResult(
                ok=False,
                records=0,
                signatures=0,
                error=(
                    "audit log missing — expected "
                    f"{tip.get('records', '?')} records"
                ),
            )
        return VerifyResult(ok=True, records=0, signatures=0)

    total = len(records)

    # --- sentinel vs the log we can actually see -----------------------
    if tip is not None:
        expected_count = tip.get("records")
        expected_tip = tip.get("tip_hash")
        if not isinstance(expected_count, int) or not isinstance(
            expected_tip, str
        ):
            return VerifyResult(
                ok=False,
                records=total,
                signatures=0,
                error="audit tip sentinel is malformed — refusing to run",
            )
        if total < expected_count:
            return VerifyResult(
                ok=False,
                records=total,
                signatures=0,
                error=(
                    f"audit log truncated — sentinel expects "
                    f"{expected_count} records, log has {total}"
                ),
            )
        # Either the sentinel is current, or it lags the log by a few
        # appends (a crash between the two writes). Re-anchor it at
        # the position it recorded instead of demanding equality.
        anchor = records[expected_count - 1][1]
        if record_hash(anchor) != expected_tip:
            return VerifyResult(
                ok=False,
                records=total,
                signatures=0,
                error=(
                    f"record #{expected_count} "
                    f"({anchor.get('type', '?')}): does not match the "
                    "audit tip sentinel — the log was modified or "
                    "truncated"
                ),
            )

    # --- walk every link; validate key records on the way -------------
    keyring: dict[str, bytes] = {}
    try:
        keyring.update(signing_keys.load_keyring(target_dir))
    except signing_keys.KeyError:
        # No keyring file and nothing to bootstrap from: the sig check
        # below reports the unknown key_id. A signing box always has
        # one of the two.
        pass
    prev_record: dict | None = None
    prev_lineno = 0
    last_sig: tuple[int, dict] | None = None
    sig_prev: dict | None = None
    sig_prev_lineno = 0
    for lineno, record in records:
        rtype = record.get("type", "?")
        if "prev_hash" in record:
            expected_link = (
                GENESIS_HASH
                if prev_record is None
                else record_hash(prev_record)
            )
            if record["prev_hash"] != expected_link:
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=0,
                    error=(
                        f"record #{lineno} ({rtype}): prev_hash mismatch — "
                        f"the log was modified after record #{prev_lineno}"
                    ),
                )
        if rtype in ("key.gen", "key.rotate"):
            error = apply_key_record(keyring, record, lineno)
            if error is not None:
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=0,
                    error=error,
                )
        elif rtype == "sig":
            last_sig = (lineno, record)
            sig_prev = prev_record
            sig_prev_lineno = prev_lineno
        prev_record = record
        prev_lineno = lineno

    if last_sig is None:
        # No anchor yet (small log, or no signing key): fall back to
        # the full check rather than trust an unanchored tip.
        return verify_log(target_dir)

    lineno, record = last_sig
    error = check_signature(
        keyring, record, lineno, sig_prev, sig_prev_lineno
    )
    if error is not None:
        return VerifyResult(
            ok=False,
            records=total,
            signatures=0,
            error=error,
        )
    return VerifyResult(ok=True, records=total, signatures=1)


def verify_log(directory: Path | None = None) -> VerifyResult:
    """Re-check the hash chain and every signature.

    Returns a VerifyResult; on failure ``error`` names the first
    broken record (number, type, reason).
    """
    keyring: dict[str, bytes] = {}
    prev_record: dict | None = None
    prev_lineno = 0
    sig_count = 0
    total = 0
    try:
        records = list(iter_records(directory))
    except AuditError as exc:
        return VerifyResult(ok=False, records=0, signatures=0, error=str(exc))

    for lineno, record in records:
        total = lineno
        rtype = record.get("type", "?")
        if "prev_hash" in record:
            expected = (
                GENESIS_HASH
                if prev_record is None
                else record_hash(prev_record)
            )
            if record["prev_hash"] != expected:
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=sig_count,
                    error=(
                        f"record #{lineno} ({rtype}): prev_hash mismatch — "
                        f"the log was modified after record #{prev_lineno}"
                    ),
                )
        # Legacy v0.1 records (no prev_hash) anchor the chain: they
        # are hashed as-is for the next record's link.
        if rtype in ("key.gen", "key.rotate"):
            error = apply_key_record(keyring, record, lineno)
            if error is not None:
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=sig_count,
                    error=error,
                )
        elif rtype == "sig":
            sig_count += 1
            error = check_signature(
                keyring, record, lineno, prev_record, prev_lineno
            )
            if error is not None:
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=sig_count,
                    error=error,
                )
        prev_record = record
        prev_lineno = lineno
    return VerifyResult(ok=True, records=total, signatures=sig_count)
