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


def append_record(record: dict, directory: Path | None = None) -> dict:
    """Atomically append one JSON record to the audit log.

    The record is chained (``v`` normalized to 2, ``prev_hash``
    added) and every ``SIG_INTERVAL`` records a ``sig`` record is
    appended when a signing key exists. Raises OSError/AuditError
    when the record cannot be persisted (callers treat that as
    fail-closed).
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
    if len(lines) % SIG_INTERVAL == 0 and signing_keys.has_key(target_dir):
        _append_signature(target_dir, record_hash(chained))
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
            key_id = record.get("key_id")
            pub_hex = record.get("public_key")
            try:
                pub = bytes.fromhex(pub_hex)
            except (TypeError, ValueError):
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=sig_count,
                    error=(
                        f"record #{lineno} ({rtype}): malformed public_key"
                    ),
                )
            if len(pub) != 32 or not key_id:
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=sig_count,
                    error=(
                        f"record #{lineno} ({rtype}): malformed key record"
                    ),
                )
            if rtype == "key.rotate":
                prev_key_id = record.get("prev_key_id")
                if keyring and prev_key_id not in keyring:
                    return VerifyResult(
                        ok=False,
                        records=total,
                        signatures=sig_count,
                        error=(
                            f"record #{lineno} (key.rotate): prev_key_id "
                            f"{prev_key_id!r} is not a known key — the key "
                            "history was modified"
                        ),
                    )
            keyring[key_id] = pub
        elif rtype == "sig":
            sig_count += 1
            key_id = record.get("key_id")
            if key_id not in keyring:
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=sig_count,
                    error=(
                        f"record #{lineno} (sig): unknown key_id "
                        f"{key_id!r} — the key history was modified"
                    ),
                )
            try:
                tip = bytes.fromhex(record["tip_hash"])
                sig = bytes.fromhex(record["signature"])
            except (TypeError, ValueError, KeyError):
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=sig_count,
                    error=(
                        f"record #{lineno} (sig): malformed tip_hash/signature"
                    ),
                )
            if prev_record is None or record.get("tip_hash") != record_hash(
                prev_record
            ):
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=sig_count,
                    error=(
                        f"record #{lineno} (sig): tip_hash does not match "
                        f"record #{prev_lineno} — the log was modified"
                    ),
                )
            if not _ed25519.verify(keyring[key_id], tip, sig):
                return VerifyResult(
                    ok=False,
                    records=total,
                    signatures=sig_count,
                    error=(
                        f"record #{lineno} (sig): bad Ed25519 signature "
                        f"(key {key_id})"
                    ),
                )
        prev_record = record
        prev_lineno = lineno
    return VerifyResult(ok=True, records=total, signatures=sig_count)
