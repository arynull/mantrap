"""Ed25519 signing-key management for the tamper-evident audit log.

The private key lives at ``<data_dir>/signing.key`` (0600, JSON with
the seed). The public keys are published inside the audit log itself
(``key.gen`` / ``key.rotate`` records, written through the
``audit_append`` callback), so ``audit --verify`` needs no private
key and old signatures stay verifiable after rotation.

Loading the private key is fail-closed on permissions: a
group/world-readable key file is treated as compromised and
refused.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from . import _ed25519

KEY_FILENAME = "signing.key"
KEY_MODE = 0o600


class KeyError(Exception):
    """Key management failure (missing key, bad permissions, ...)."""


def key_path(directory: Path) -> Path:
    return directory / KEY_FILENAME


def key_id_for_public_key(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def _check_permissions(path: Path) -> None:
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise KeyError(
            f"signing key {path} has permissions {mode:04o}; "
            "refusing to use a key readable by group/other "
            "(treat as compromised: rotate with `mantrap keygen --rotate` "
            "after fixing permissions)"
        )


def load_seed(directory: Path) -> tuple[bytes, str]:
    """Load the private seed; returns (seed, key_id). Fail-closed."""
    path = key_path(directory)
    if not path.is_file():
        raise KeyError(f"no signing key at {path}; run `mantrap keygen` first")
    _check_permissions(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        seed = base64.b64decode(data["seed_b64"])
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise KeyError(f"cannot read signing key at {path}: {exc}") from exc
    if len(seed) != 32:
        raise KeyError(f"signing key at {path} is corrupt (bad seed length)")
    public_key = _ed25519.public_key_from_seed(seed)
    return seed, key_id_for_public_key(public_key)


def has_key(directory: Path) -> bool:
    return key_path(directory).is_file()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate(directory: Path, audit_append=None) -> tuple[str, bytes]:
    """Create a new signing key (0600). Returns (key_id, public_key).

    Refuses to overwrite an existing key — use rotate() instead.
    When ``audit_append`` is given, a ``key.gen`` record is written
    through it so signatures are verifiable from the log alone.
    """
    path = key_path(directory)
    if path.exists():
        raise KeyError(
            f"signing key already exists at {path}; "
            "use `mantrap keygen --rotate` to replace it"
        )
    directory.mkdir(parents=True, exist_ok=True)
    seed = os.urandom(32)
    public_key = _ed25519.public_key_from_seed(seed)
    key_id = key_id_for_public_key(public_key)
    payload = json.dumps(
        {
            "kty": "ed25519",
            "key_id": key_id,
            "seed_b64": base64.b64encode(seed).decode(),
        }
    ).encode("utf-8")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, KEY_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    # umask could only narrow 0600 further; enforce exactly 0600.
    os.chmod(path, KEY_MODE)
    if audit_append is not None:
        audit_append(
            {
                "ts": _utc_now_iso(),
                "type": "key.gen",
                "key_id": key_id,
                "public_key": public_key.hex(),
            }
        )
    return key_id, public_key


def rotate(directory: Path, audit_append=None) -> tuple[str, bytes, str]:
    """Replace the signing key, keeping a 0600 backup of the old one.

    Returns (new_key_id, new_public_key, old_key_id). When
    ``audit_append`` is given, a ``key.rotate`` record chaining old ->
    new is written through it.
    """
    path = key_path(directory)
    if not path.is_file():
        raise KeyError(f"no signing key at {path}; run `mantrap keygen` first")
    _check_permissions(path)
    old_data = path.read_bytes()
    old_pub = _ed25519.public_key_from_seed(
        base64.b64decode(json.loads(old_data.decode("utf-8"))["seed_b64"])
    )
    old_key_id = key_id_for_public_key(old_pub)
    backup = directory / (KEY_FILENAME + ".prev")
    # Best-effort backup rotation of the previous backup.
    try:
        if backup.exists():
            backup.unlink()
    except OSError:
        pass
    os.replace(path, backup)
    try:
        new_key_id, new_pub = generate(directory)
    except BaseException:
        # Restore the old key; a half-rotated state must not persist.
        os.replace(backup, path)
        raise
    if audit_append is not None:
        audit_append(
            {
                "ts": _utc_now_iso(),
                "type": "key.rotate",
                "key_id": new_key_id,
                "public_key": new_pub.hex(),
                "prev_key_id": old_key_id,
            }
        )
    return new_key_id, new_pub, old_key_id
