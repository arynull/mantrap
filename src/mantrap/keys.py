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
# Public keys of every key ever generated or rotated on this box.
# Lets the verify-on-start preflight resolve a `sig` record's key_id
# without re-deriving the key history from the log. Purely derived
# state: it can always be rebuilt from the key records themselves.
KEYRING_FILENAME = "signing.keyring.json"
KEYRING_MODE = 0o600


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


# --- public-key ring (verify-on-start support) ---------------------------


def keyring_path(directory: Path) -> Path:
    return directory / KEYRING_FILENAME


def _write_keyring(directory: Path, keyring: dict[str, bytes]) -> None:
    """Persist the public-key ring (0600), replacing atomically."""
    path = keyring_path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {key_id: pub.hex() for key_id, pub in sorted(keyring.items())},
        sort_keys=True,
    ) + "\n"
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, KEYRING_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, KEYRING_MODE)
        os.replace(tmp, path)
        os.chmod(path, KEYRING_MODE)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise KeyError(f"cannot write keyring {path}: {exc}") from exc


def add_public_key(
    directory: Path, key_id: str, public_key: bytes
) -> None:
    """Record a public key in the ring (maintained by generate/rotate)."""
    keyring = _read_keyring_file(directory) or {}
    keyring[key_id] = public_key
    _write_keyring(directory, keyring)


def _read_keyring_file(directory: Path) -> dict[str, bytes] | None:
    """The ring file as {key_id: pub}, or None when it does not exist."""
    path = keyring_path(directory)
    if not path.is_file():
        return None
    _check_permissions(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise KeyError(f"cannot read keyring {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise KeyError(f"keyring {path} is not a JSON object")
    keyring: dict[str, bytes] = {}
    for key_id, pub_hex in data.items():
        if not isinstance(key_id, str) or not isinstance(pub_hex, str):
            raise KeyError(f"keyring {path} has a malformed entry")
        try:
            pub = bytes.fromhex(pub_hex)
        except ValueError:
            raise KeyError(f"keyring {path} has a malformed key") from None
        if len(pub) != 32:
            raise KeyError(f"keyring {path} has a malformed key")
        keyring[key_id] = pub
    return keyring


def load_keyring(directory: Path) -> dict[str, bytes]:
    """Public keys known for this data dir; bootstrap from the log.

    Reads ``signing.keyring.json`` when present (0600; a
    group/world-readable ring is treated as compromised, same rule
    as the private key). When it is missing, rebuilds it from the
    log's ``key.gen``/``key.rotate`` records — exactly the key
    history ``audit --verify`` already trusts — folding each through
    the shared ``audit.apply_key_record`` rules rather than
    reimplementing them, and only persists the result once
    ``audit.verify_log`` agrees the log is intact. A bootstrap that
    cannot be verified raises: fail-closed, never trust a rebuilt
    keyring blindly.

    Returns an empty mapping when there is neither a ring file nor
    any key record — an unsigned fresh install has nothing to
    resolve, and the signature checks that use this simply have no
    signature to check.
    """
    keyring = _read_keyring_file(directory)
    if keyring is not None:
        return keyring
    # Local import: audit imports this module, so the cycle is
    # resolved at call time rather than at import time.
    from . import audit

    rebuilt: dict[str, bytes] = {}
    found = False
    try:
        for lineno, record in audit.iter_records(directory):
            if record.get("type") in ("key.gen", "key.rotate"):
                found = True
                error = audit.apply_key_record(rebuilt, record, lineno)
                if error is not None:
                    raise KeyError(
                        f"cannot rebuild keyring from the audit log: {error}"
                    )
    except audit.AuditError as exc:
        raise KeyError(
            f"cannot rebuild keyring from the audit log: {exc}"
        ) from exc
    if not found:
        return {}
    # Trust nothing that verify_log does not also accept.
    result = audit.verify_log(directory)
    if not result.ok:
        raise KeyError(
            "cannot rebuild keyring: the audit log failed verification "
            f"({result.error})"
        )
    _write_keyring(directory, rebuilt)
    return rebuilt


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
    # Maintain the public-key ring verify-on-start uses to resolve
    # sig key_ids without scanning the log.
    add_public_key(directory, key_id, public_key)
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
    # The new key was already ringed by the generate() call above;
    # ring the retired key too so old signatures stay resolvable.
    add_public_key(directory, old_key_id, old_pub)
    return new_key_id, new_pub, old_key_id
