"""Workspace snapshots and rollback (host-side, rsync-based).

A snapshot copies a policy's first writable mount into
``<data_dir>/snapshots/<policy-sha8>/<timestamp>/`` with a manifest
of every file's size and SHA-256. ``rollback`` restores it
(``--dry-run`` shows the file-level diff first). Snapshot creation
and rollback are themselves audit-logged.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SNAPSHOTS_DIRNAME = "snapshots"
MANIFEST_FILENAME = "manifest.json"
DATA_DIRNAME = "data"


class SnapshotError(Exception):
    """Snapshot/rollback failure."""


@dataclass
class SnapshotMeta:
    snap_id: str  # "<policy-sha8>/<timestamp>"
    policy_sha8: str
    timestamp: str  # directory name, sortable
    ts_iso: str
    message: str
    workspace: str
    files: int
    path: Path


def _rsync() -> str:
    exe = shutil.which("rsync")
    if exe is None:
        raise SnapshotError(
            "rsync is required for snapshots but was not found on PATH"
        )
    return exe


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scan(workspace: Path) -> list[dict]:
    """Manifest entries for every regular file under workspace."""
    entries = []
    for root, _dirs, files in os.walk(workspace):
        for name in files:
            full = Path(root) / name
            if not full.is_file() or full.is_symlink():
                # Symlinks are recorded by target, not followed.
                if full.is_symlink():
                    entries.append(
                        {
                            "path": str(full.relative_to(workspace)),
                            "symlink": os.readlink(full),
                        }
                    )
                continue
            rel = str(full.relative_to(workspace))
            entries.append(
                {
                    "path": rel,
                    "size": full.stat().st_size,
                    "sha256": _hash_file(full),
                }
            )
    entries.sort(key=lambda e: e["path"])
    return entries


def snapshots_root(data_dir: Path) -> Path:
    return data_dir / SNAPSHOTS_DIRNAME


def create_snapshot(
    workspace: Path,
    *,
    data_dir: Path,
    policy_sha256: str,
    message: str | None = None,
) -> SnapshotMeta:
    """Snapshot workspace; returns the snapshot metadata."""
    if not workspace.is_dir():
        raise SnapshotError(f"workspace is not a directory: {workspace}")
    rsync = _rsync()
    policy_sha8 = policy_sha256[:8]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    dest = snapshots_root(data_dir) / policy_sha8 / stamp
    data_dest = dest / DATA_DIRNAME
    data_dest.mkdir(parents=True)
    try:
        proc = subprocess.run(
            [rsync, "-a", "--delete", str(workspace) + "/", str(data_dest) + "/"],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SnapshotError(f"rsync failed: {exc}") from exc
    if proc.returncode != 0:
        raise SnapshotError(f"rsync failed: {proc.stderr.strip()}")
    entries = _scan(data_dest)
    meta = {
        "snap_id": f"{policy_sha8}/{stamp}",
        "ts": datetime.now(timezone.utc).isoformat(),
        "message": message or "",
        "policy_sha256": policy_sha256,
        "workspace": str(workspace),
        "files": entries,
    }
    (dest / MANIFEST_FILENAME).write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return SnapshotMeta(
        snap_id=meta["snap_id"],
        policy_sha8=policy_sha8,
        timestamp=stamp,
        ts_iso=meta["ts"],
        message=meta["message"],
        workspace=str(workspace),
        files=len(entries),
        path=dest,
    )


def _load_meta(path: Path) -> SnapshotMeta:
    meta = json.loads((path / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    stamp = path.name
    policy_sha8 = path.parent.name
    return SnapshotMeta(
        snap_id=f"{policy_sha8}/{stamp}",
        policy_sha8=policy_sha8,
        timestamp=stamp,
        ts_iso=meta.get("ts", ""),
        message=meta.get("message", ""),
        workspace=meta.get("workspace", ""),
        files=len(meta.get("files", [])),
        path=path,
    )


def list_snapshots(data_dir: Path) -> list[SnapshotMeta]:
    """All snapshots, newest first."""
    root = snapshots_root(data_dir)
    metas: list[SnapshotMeta] = []
    if root.is_dir():
        for policy_dir in sorted(root.iterdir()):
            if not policy_dir.is_dir():
                continue
            for snap_dir in sorted(policy_dir.iterdir()):
                manifest = snap_dir / MANIFEST_FILENAME
                if snap_dir.is_dir() and manifest.is_file():
                    try:
                        metas.append(_load_meta(snap_dir))
                    except (OSError, ValueError):
                        continue
    metas.sort(key=lambda m: (m.policy_sha8, m.timestamp), reverse=True)
    return metas


def find_snapshot(data_dir: Path, snap_id: str) -> SnapshotMeta:
    """Resolve a snap id (full "<sha8>/<stamp>" or bare "<stamp>")."""
    if "/" in snap_id:
        policy_sha8, stamp = snap_id.split("/", 1)
        candidate = snapshots_root(data_dir) / policy_sha8 / stamp
        if (candidate / MANIFEST_FILENAME).is_file():
            return _load_meta(candidate)
        raise SnapshotError(f"snapshot not found: {snap_id}")
    matches = [m for m in list_snapshots(data_dir) if m.timestamp == snap_id]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SnapshotError(f"snapshot not found: {snap_id}")
    raise SnapshotError(
        f"snapshot id {snap_id!r} is ambiguous: "
        + ", ".join(m.snap_id for m in matches)
    )


@dataclass
class FileDiff:
    path: str
    change: str  # "added" | "modified" | "deleted"


def diff_workspace(meta: SnapshotMeta) -> list[FileDiff]:
    """Compare the live workspace against the snapshot manifest.

    "added" = in workspace but not in the snapshot, "deleted" = in
    the snapshot but missing from the workspace, "modified" = present
    in both with different content.
    """
    manifest = json.loads(
        (meta.path / MANIFEST_FILENAME).read_text(encoding="utf-8")
    )
    snap_files = {e["path"]: e for e in manifest.get("files", [])}
    workspace = Path(meta.workspace)
    live = {e["path"]: e for e in _scan(workspace)} if workspace.is_dir() else {}
    diffs: list[FileDiff] = []
    for path, entry in sorted(live.items()):
        old = snap_files.get(path)
        if old is None:
            diffs.append(FileDiff(path, "added"))
        elif old.get("symlink") != entry.get("symlink") or (
            "sha256" in entry and old.get("sha256") != entry.get("sha256")
        ):
            diffs.append(FileDiff(path, "modified"))
    for path in sorted(snap_files):
        if path not in live:
            diffs.append(FileDiff(path, "deleted"))
    return diffs


def rollback(
    meta: SnapshotMeta, *, dry_run: bool = False
) -> list[FileDiff]:
    """Restore the workspace from the snapshot.

    With dry_run, only computes and returns the diff. Otherwise
    rsyncs back (with --delete) and verifies every restored file
    against the manifest; returns the applied diff.
    """
    diffs = diff_workspace(meta)
    if dry_run:
        return diffs
    workspace = Path(meta.workspace)
    if not workspace.is_dir():
        raise SnapshotError(f"workspace is missing: {workspace}")
    rsync = _rsync()
    data_src = meta.path / DATA_DIRNAME
    try:
        proc = subprocess.run(
            [rsync, "-a", "--delete", str(data_src) + "/", str(workspace) + "/"],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SnapshotError(f"rsync failed: {exc}") from exc
    if proc.returncode != 0:
        raise SnapshotError(f"rsync failed: {proc.stderr.strip()}")
    # Verify the restore against the manifest.
    remaining = diff_workspace(meta)
    if remaining:
        raise SnapshotError(
            "rollback verification failed; still differing: "
            + ", ".join(f"{d.change}:{d.path}" for d in remaining[:5])
        )
    return diffs
