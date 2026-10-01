"""Policy loading and validation.

Policy file resolution order:
  1. ``--policy FILE`` when given explicitly.
  2. ``./mantrap.yaml`` in the current working directory.
  3. ``~/.mantrap/mantrap.yaml`` (the data dir may be overridden
     with the ``MANTRAP_DATA_DIR`` environment variable).

Fail-closed: when no file is found, or the file is invalid, the
run is refused before anything executes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_TIMEOUT_S = 300

KNOWN_TOP_KEYS = {"fs", "env", "limits"}
KNOWN_FS_KEYS = {"read", "write"}
KNOWN_ENV_KEYS = {"allow"}
KNOWN_LIMIT_KEYS = {"timeout", "memory", "cpu_seconds", "nproc"}


class PolicyError(ValueError):
    """Raised when a policy file is missing or invalid."""


@dataclass
class Policy:
    """A validated policy document."""

    fs_read: list[str] = field(default_factory=list)
    fs_write: list[str] = field(default_factory=list)
    env_allow: list[str] = field(default_factory=list)
    timeout: int | float = DEFAULT_TIMEOUT_S
    memory: int | None = None
    cpu_seconds: int | None = None
    nproc: int | None = None
    source: str = ""


def data_dir() -> Path:
    """User state directory (audit log lives here)."""
    override = os.environ.get("MANTRAP_DATA_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".mantrap"


def resolve_policy_path(explicit: str | None) -> Path:
    """Return the policy file to use, or raise PolicyError."""
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise PolicyError(f"policy file not found: {path}")
        return path
    local = Path.cwd() / "mantrap.yaml"
    if local.is_file():
        return local
    fallback = data_dir() / "mantrap.yaml"
    if fallback.is_file():
        return fallback
    raise PolicyError(
        "no policy file found: looked for ./mantrap.yaml and "
        f"{fallback} (pass --policy FILE or run `mantrap init`)"
    )


def _check_path_list(entries: object, key: str) -> list[str]:
    if entries is None:
        return []
    if not isinstance(entries, list) or not all(
        isinstance(e, str) for e in entries
    ):
        raise PolicyError(f"policy key {key!r} must be a list of strings")
    checked: list[str] = []
    for raw in entries:
        if not os.path.isabs(raw):
            raise PolicyError(
                f"policy path must be absolute: {key} entry {raw!r}"
            )
        # Reject ".." outright: "resolve outside themselves" is
        # undecidable textually once symlinks are involved, so any
        # parent-component is fail-closed rather than normalized away.
        if ".." in raw.split("/"):
            raise PolicyError(
                f"policy path must not contain '..': {key} entry {raw!r}"
            )
        normalized = os.path.normpath(raw)
        if not os.path.exists(normalized):
            raise PolicyError(
                f"policy path does not exist: {key} entry {raw!r}"
            )
        checked.append(normalized)
    return checked


def load_policy(path: Path) -> tuple[Policy, str]:
    """Load and validate a policy file.

    Returns (policy, sha256_hex_of_file_bytes).
    """
    import hashlib

    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    digest = hashlib.sha256(raw_bytes).hexdigest()
    try:
        data = yaml.safe_load(raw_bytes.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise PolicyError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PolicyError(f"policy {path} must be a mapping at top level")
    unknown = set(data) - KNOWN_TOP_KEYS
    if unknown:
        raise PolicyError(
            f"unknown policy key(s): {', '.join(sorted(map(str, unknown)))}"
        )

    fs = data.get("fs", {})
    if fs is None:
        fs = {}
    if not isinstance(fs, dict):
        raise PolicyError("policy key 'fs' must be a mapping")
    unknown_fs = set(fs) - KNOWN_FS_KEYS
    if unknown_fs:
        raise PolicyError(
            "unknown policy key(s) under 'fs': "
            + ", ".join(sorted(map(str, unknown_fs)))
        )

    env = data.get("env", {})
    if env is None:
        env = {}
    if not isinstance(env, dict):
        raise PolicyError("policy key 'env' must be a mapping")
    unknown_env = set(env) - KNOWN_ENV_KEYS
    if unknown_env:
        raise PolicyError(
            "unknown policy key(s) under 'env': "
            + ", ".join(sorted(map(str, unknown_env)))
        )

    limits = data.get("limits", {})
    if limits is None:
        limits = {}
    if not isinstance(limits, dict):
        raise PolicyError("policy key 'limits' must be a mapping")
    unknown_limits = set(limits) - KNOWN_LIMIT_KEYS
    if unknown_limits:
        raise PolicyError(
            "unknown policy key(s) under 'limits': "
            + ", ".join(sorted(map(str, unknown_limits)))
        )

    allow = env.get("allow", [])
    if allow is None:
        allow = []
    if not isinstance(allow, list) or not all(
        isinstance(e, str) for e in allow
    ):
        raise PolicyError("policy key 'env.allow' must be a list of strings")
    for name in allow:
        if "*" in name:
            raise PolicyError(
                "policy key 'env.allow' does not support wildcards "
                f"(got {name!r}); list each variable explicitly"
            )
        if (
            not name
            or not (name[0].isalpha() or name[0] == "_")
            or not all(c.isalnum() or c == "_" for c in name)
        ):
            raise PolicyError(
                f"invalid environment variable name in 'env.allow': {name!r}"
            )

    timeout = limits.get("timeout", DEFAULT_TIMEOUT_S)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise PolicyError("policy key 'limits.timeout' must be a number")
    if timeout <= 0:
        raise PolicyError("policy key 'limits.timeout' must be positive")

    def _opt_int(key: str) -> int | None:
        value = limits.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise PolicyError(f"policy key 'limits.{key}' must be an integer")
        if value <= 0:
            raise PolicyError(f"policy key 'limits.{key}' must be positive")
        return value

    policy = Policy(
        fs_read=_check_path_list(fs.get("read"), "fs.read"),
        fs_write=_check_path_list(fs.get("write"), "fs.write"),
        env_allow=list(allow),
        timeout=timeout,
        memory=_opt_int("memory"),
        cpu_seconds=_opt_int("cpu_seconds"),
        nproc=_opt_int("nproc"),
        source=str(path),
    )
    return policy, digest
