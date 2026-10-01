"""Audit log: one JSON object per line, forward-compatible schema.

Each sandboxed run appends exactly one record. Writes are atomic
(write a temp file in the same directory, then rename) so a crash
mid-write cannot leave a half-written line. The ``v`` field keeps
the schema forward-compatible for later hash-chaining.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

from .policy import data_dir

AUDIT_FILENAME = "audit.log"


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
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": "run",
        "policy_sha256": policy_sha256,
        "argv": list(argv),
        "uid": os.getuid(),
        "exit_code": exit_code,
        "duration_s": duration_s,
        "killed_by_limit": killed_by_limit,
        "proc_fallback": proc_fallback,
    }
    directory = data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / AUDIT_FILENAME
    existing = b""
    if target.exists():
        existing = target.read_bytes()
    line = (json.dumps(record) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(
        dir=str(directory), prefix="audit.", suffix=".tmp"
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
