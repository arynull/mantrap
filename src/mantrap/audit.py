"""Audit log: one JSON object per line, forward-compatible schema.

Run records (type "run") use the exact v0.1 schema. Network records
(type "net.allow" / "net.deny") share the same atomic append path.
The ``v`` field keeps the schema forward-compatible for later
hash-chaining.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .policy import data_dir

AUDIT_FILENAME = "audit.log"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_record(record: dict, directory: Path | None = None) -> dict:
    """Atomically append one JSON record to the audit log.

    Uses write-temp-then-rename so a crash cannot leave a
    half-written line. Raises OSError when the record cannot be
    persisted (callers treat that as fail-closed).
    """
    target_dir = directory if directory is not None else data_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / AUDIT_FILENAME
    existing = b""
    if target.exists():
        existing = target.read_bytes()
    line = (json.dumps(record) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target_dir), prefix="audit.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            if existing:
                handle.write(existing.decode("utf-8"))
            handle.write(line.decode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return record


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
        "v": 1,
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
