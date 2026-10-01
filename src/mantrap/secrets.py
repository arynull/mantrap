"""Credential broker: scoped secrets injected into the sandbox only.

A policy lists secret NAMES plus where each value comes from
(`env:VAR`, `file:PATH`, `keyring:SERVICE/USER`). The secret VALUE
never appears in the policy file, the audit log, or error messages:
resolution failures name the secret NAME and the source, never the
value.

At run time the broker resolves each value and the sandbox layer
injects it with `--setenv` into the sandboxed process only. The
audit record stores a scrubbed copy of argv (see `scrub_argv`),
so a secret expanded onto the command line by the user's shell
cannot leak into the log either.
"""

from __future__ import annotations

import os
import stat

SECRET_SOURCES = ("env", "file", "keyring")


class SecretsError(ValueError):
    """Raised when a secret cannot be resolved (fail-closed)."""


def _resolve_env(name: str, var: str) -> str:
    try:
        return os.environ[var]
    except KeyError:
        raise SecretsError(
            f"secret {name!r}: environment variable {var!r} is not set"
        ) from None


def _resolve_file(name: str, path: str) -> str:
    if not os.path.isfile(path):
        raise SecretsError(
            f"secret {name!r}: file {path!r} does not exist "
            "or is not a regular file"
        )
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError as exc:
        raise SecretsError(
            f"secret {name!r}: cannot stat file {path!r}: "
            f"{type(exc).__name__}"
        ) from None
    if mode & 0o077:
        raise SecretsError(
            f"secret {name!r}: file {path!r} is readable by group/other; "
            "refusing (use mode 0600 or 0400)"
        )
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise SecretsError(
            f"secret {name!r}: cannot read file {path!r}: "
            f"{type(exc).__name__}"
        ) from None
    if not lines:
        raise SecretsError(f"secret {name!r}: file {path!r} is empty")
    return lines[0]


def _resolve_keyring(name: str, spec: str) -> str:
    try:
        import secretstorage  # type: ignore[import-not-found]
    except ImportError:
        raise SecretsError(
            f"secret {name!r}: keyring source needs the 'secretstorage' "
            "package, which is not installed"
        ) from None
    service, _, user = spec.partition("/")
    if not service or not user:
        raise SecretsError(
            f"secret {name!r}: keyring source must be SERVICE/USER "
            f"(got {spec!r})"
        )
    try:
        connection = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(connection)
        items = list(collection.search_items(
            {"service": service, "username": user}))
        if not items:
            raise LookupError("not found")
        item = items[0]
        if item.is_locked():
            item.unlock()
        value = item.get_secret()
    except Exception as exc:  # noqa: BLE001 - map everything, leak nothing
        raise SecretsError(
            f"secret {name!r}: keyring lookup failed for "
            f"{service!r}/{user!r}: {type(exc).__name__}"
        ) from None
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            raise SecretsError(
                f"secret {name!r}: keyring value is not valid UTF-8"
            ) from None
    return value


def resolve_secrets(spec: dict[str, dict]) -> dict[str, str]:
    """Resolve every secret NAME in spec to its value.

    Raises SecretsError on the first unresolvable secret (fail-closed:
    nothing runs with a partially-resolved set). Never includes a
    secret value in any error message.
    """
    resolved: dict[str, str] = {}
    for name in sorted(spec):
        entry = spec[name]
        if not isinstance(entry, dict) or len(entry) != 1:
            raise SecretsError(
                f"secret {name!r}: must map exactly one source kind "
                "to its argument"
            )
        kind, arg = next(iter(entry.items()))
        if kind not in SECRET_SOURCES:
            raise SecretsError(
                f"secret {name!r}: unknown source {kind!r} "
                f"(expected one of {', '.join(SECRET_SOURCES)})"
            )
        if kind == "env":
            resolved[name] = _resolve_env(name, arg)
        elif kind == "file":
            resolved[name] = _resolve_file(name, arg)
        else:
            resolved[name] = _resolve_keyring(name, arg)
    return resolved


def scrub_argv(argv: list[str], secrets: dict[str, str]) -> list[str]:
    """Copy argv with every secret value occurrence replaced by `***`.

    Longest values first so overlapping secrets scrub fully. Empty
    values are skipped (replacing "" would corrupt everything).
    The workload still receives the real argv; only the recorded
    copy is scrubbed.
    """
    values = sorted(
        {v for v in secrets.values() if v}, key=len, reverse=True
    )
    if not values:
        return list(argv)
    scrubbed = []
    for element in argv:
        for value in values:
            if value in element:
                element = element.replace(value, "***")
        scrubbed.append(element)
    return scrubbed


def mask_value(value: str) -> str:
    """Display form of a secret value for `--dry-run` output."""
    return f"*** ({len(value)} chars)"


def mask_argv(argv: list[str], secret_names: set[str]) -> list[str]:
    """Copy a bwrap argv with secret `--setenv NAME value` masked.

    Any `--setenv NAME <val>` where NAME is in secret_names has
    `<val>` replaced by `***`. Other elements pass through
    untouched.
    """
    masked = list(argv)
    i = 0
    while i + 2 < len(masked):
        if masked[i] == "--setenv" and masked[i + 1] in secret_names:
            masked[i + 2] = "***"
            i += 3
        else:
            i += 1
    return masked
