"""Approval gates: the mantrap interlock.

A gate rule matches an action the workload is about to take (executing
a binary, opening an egress request to a domain, mounting a writable
path) and decides it before anything runs:

- ``allow``: proceed, audit the decision.
- ``deny``: refuse fail-closed, audit, raise :class:`GateDenied`.
- ``ask``: pause the workload and prompt the operator on the
  controlling terminal (part B wires the pause in).

Rules evaluate in policy order; the first match wins (firewall order,
so put specific allows before broad asks).

Path-kind patterns (``exec.path``, ``fs.write``) are canonicalized
with ``os.path.realpath`` at parse time and candidate values at
decision time, so symlink aliases and ``..`` spellings match the same
rule; this can only add matches, never remove them (fail-closed
direction preserved).

Gate decisions never carry secret values: details name binaries,
domains, and mount paths only.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

MATCH_KINDS = ("exec.path", "net.domain", "fs.write")
ACTIONS = ("allow", "deny", "ask")


class GateError(ValueError):
    """Raised when a `gates:` policy block is malformed (policy time)."""


class GateDenied(Exception):
    """Raised when a gate denied an action (run time, fail-closed)."""

    def __init__(self, rule_id: str, detail: str = "") -> None:
        self.rule_id = rule_id
        self.detail = detail
        message = f"gate {rule_id} denied"
        if detail:
            message += f": {detail}"
        super().__init__(message)


@dataclass
class GateRule:
    """One parsed approval rule."""

    id: str  # "gate-0", "gate-1", ... in policy order
    match_kind: str  # "exec.path" | "net.domain" | "fs.write"
    pattern: str  # glob for exec.path/net.domain; abs prefix for fs.write
    action: str  # "allow" | "deny" | "ask"
    description: str  # for prompts; explicit or generated


def parse_gates(raw: object) -> list[GateRule]:
    """Parse the YAML value of `gates:` into ordered gate rules.

    ``None`` (absent block) yields ``[]``. Anything malformed raises
    :class:`GateError`, which propagates out of policy loading as-is.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise GateError("policy key 'gates' must be a list of rules")
    rules: list[GateRule] = []
    for index, entry in enumerate(raw):
        where = f"gates[{index}]"
        if not isinstance(entry, dict):
            raise GateError(f"{where}: rule must be a mapping")
        extra = set(entry) - {"match", "action", "description"}
        if extra or "match" not in entry or "action" not in entry:
            raise GateError(
                f"{where}: rule must have exactly 'match' and 'action' "
                "plus optional 'description'"
            )
        match = entry["match"]
        if not isinstance(match, dict) or len(match) != 1:
            raise GateError(
                f"{where}: 'match' must be a mapping with exactly one key "
                f"(one of {', '.join(MATCH_KINDS)})"
            )
        kind, pattern = next(iter(match.items()))
        if kind not in MATCH_KINDS:
            raise GateError(
                f"{where}: unknown match kind {kind!r} "
                f"(expected one of {', '.join(MATCH_KINDS)})"
            )
        if not isinstance(pattern, str) or not pattern:
            raise GateError(f"{where}: match pattern must be a non-empty string")
        if kind == "fs.write" and not os.path.isabs(pattern):
            raise GateError(
                f"{where}: fs.write pattern must be an absolute path "
                f"(got {pattern!r})"
            )
        action = entry["action"]
        if action not in ACTIONS:
            raise GateError(
                f"{where}: action must be one of {', '.join(ACTIONS)} "
                f"(got {action!r})"
            )
        if kind in ("exec.path", "fs.write"):
            # resolve symlink spellings: a rule must match every alias of the same file
            pattern = os.path.realpath(pattern)
        description = entry.get("description")
        if description is None:
            description = f"{kind} matches {pattern!r}"
        elif not isinstance(description, str) or not description:
            raise GateError(f"{where}: 'description' must be a non-empty string")
        if kind == "net.domain":
            pattern = pattern.lower()
        rules.append(
            GateRule(
                id=f"gate-{index}",
                match_kind=kind,
                pattern=pattern,
                action=action,
                description=description,
            )
        )
    return rules


def _tty_prompt(prompt_text: str, tty_path: str = "/dev/tty") -> str | None:
    """Write the prompt to the controlling terminal, read one line.

    Returns None when there is no terminal (fail-closed: the caller
    denies). Any OSError opening or reading the tty means no answer.

    The tty is opened twice (write-only, then read-only): opening a
    terminal in ``r+`` update mode raises ``UnsupportedOperation``
    because terminals are not seekable, which would make every ask
    degrade to no-tty. The write open uses ``os.open`` without
    ``O_CREAT`` so a missing path can never be created as a file.
    """
    try:
        fd = os.open(tty_path, os.O_WRONLY)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "w") as out:
            out.write(prompt_text)
            out.flush()
    except OSError:
        return None
    try:
        with open(tty_path) as inp:
            return inp.readline()
    except OSError:
        return None


class GateSession:
    """Per-run gate state: decisions, ask cache, audit hook, prompting."""

    def __init__(
        self,
        rules: list[GateRule],
        *,
        auto_yes: bool = False,
        approve_all: bool = False,
        audit_append: Callable[[dict], object] | None = None,
        prompt_io: Callable[[str], str | None] | None = None,
    ) -> None:
        self.rules = list(rules)
        self.auto_yes = auto_yes
        self.approve_all = approve_all
        if audit_append is None:
            audit_append = lambda record: None  # noqa: E731 - trivial default
        self.audit_append = audit_append
        self.prompt_io = prompt_io if prompt_io is not None else _tty_prompt
        self._ask_cache: dict[tuple[str, str], str] = {}
        self._prompt_lock = threading.Lock()
        self._pgid: int | None = None

    def set_pgid(self, pgid: int | None) -> None:
        """Store the workload's process-group id for the SIGSTOP interlock.

        `check_net_domain` called without an explicit pgid falls back
        to this stored value, so the proxy hook (which only knows the
        domain) still pauses the right process group.
        """
        self._pgid = pgid

    def decide(self, kind: str, value: str) -> GateRule | None:
        """Return the first rule matching `value`, else None.

        **First match wins** (firewall order — put specific allows
        before broad asks). Matching per kind:

        - ``exec.path``: ``fnmatch.fnmatchcase(value, pattern)``;
          candidate spellings canonicalized via ``exec_candidates``,
          pattern canonicalized at parse time.
        - ``net.domain``: case-insensitive glob (pattern is stored
          lowercased, value is lowered before matching).
        - ``fs.write``: value canonicalized with ``os.path.realpath``
          before the prefix compare; exact path or strict child
          (``/etc`` matches ``/etc`` and ``/etc/passwd`` but not
          ``/etcetera``).
        """
        for rule in self.rules:
            if rule.match_kind != kind:
                continue
            if kind == "exec.path":
                if fnmatch.fnmatchcase(value, rule.pattern):
                    return rule
            elif kind == "net.domain":
                if fnmatch.fnmatchcase(value.lower(), rule.pattern):
                    return rule
            elif kind == "fs.write":
                # resolve alias spellings to the canonical path before comparing
                value = os.path.realpath(value)
                prefix = rule.pattern.rstrip("/") + "/"
                if value == rule.pattern or value.startswith(prefix):
                    return rule
        return None

    @staticmethod
    def exec_candidates(argv0: str) -> list[str]:
        """Candidate path spellings an `exec.path` glob may match.

        Raw spelling first plus canonical spellings, so symlink
        aliases and ``..`` spellings match the same rule. Includes
        the ``PATH`` resolution when argv0 names a bare command, so
        a ``curl`` invocation matches a ``/usr/bin/curl`` glob.
        """
        if "/" in argv0:
            return list(dict.fromkeys([argv0, os.path.realpath(argv0)]))
        resolved = shutil.which(argv0)
        if resolved:
            return list(
                dict.fromkeys([argv0, resolved, os.path.realpath(resolved)])
            )
        return [argv0]

    def check_exec_path(self, argv0: str) -> Literal["allow"]:
        """Gate an exec before it starts; deny raises GateDenied.

        No matching rule allows silently (no audit record).
        """
        for candidate in self.exec_candidates(argv0):
            rule = self.decide("exec.path", candidate)
            if rule is not None:
                return self._enforce_start(rule, f"exec {argv0}")
        return "allow"

    def check_fs_writes(self, write_mounts: list[str]) -> Literal["allow"]:
        """Gate requested write mounts before the sandbox starts.

        The first matching mount in order decides; deny raises
        GateDenied. No match allows silently (no audit record).
        """
        for mount in write_mounts:
            rule = self.decide("fs.write", mount)
            if rule is not None:
                return self._enforce_start(rule, f"write mount {mount}")
        return "allow"

    def _enforce_start(self, rule: GateRule, detail: str) -> Literal["allow"]:
        """Enforce a start-time rule: allow passes, deny/denied-ask raises."""
        if rule.action == "allow":
            self.audit_gate(rule, "allow", "rule", detail)
            return "allow"
        if rule.action == "deny":
            self.audit_gate(rule, "deny", "rule", detail)
            raise GateDenied(rule.id, detail)
        decision = self.resolve_ask(rule, detail, pgid=None)
        if decision == "deny":
            raise GateDenied(rule.id, detail)
        return "allow"

    def check_net_domain(
        self, domain: str, pgid: int | None = None
    ) -> Literal["allow", "deny"]:
        """Gate one egress request (called per request by the proxy hook).

        No matching rule allows silently (no audit record); otherwise
        the rule's action decides, with `ask` pausing `pgid` for the
        operator prompt.
        """
        rule = self.decide("net.domain", domain)
        if rule is None:
            return "allow"
        detail = f"request to {domain}"
        if rule.action == "allow":
            self.audit_gate(rule, "allow", "rule", detail)
            return "allow"
        if rule.action == "deny":
            self.audit_gate(rule, "deny", "rule", detail)
            return "deny"
        if pgid is None:
            pgid = self._pgid
        return self.resolve_ask(rule, detail, pgid=pgid)

    def resolve_ask(
        self, rule: GateRule, detail: str, pgid: int | None = None
    ) -> Literal["allow", "deny"]:
        """Resolve an `ask` rule: flags, remembered answers, then TTY.

        Precedence: remembered "always" answer, ``--approve-all``,
        ``--yes`` (deny, fail-closed for CI), then the interactive
        prompt with the workload stopped. Every outcome is audited
        with its decider; any path without an explicit allow denies.
        """
        key = (rule.id, detail)
        if key in self._ask_cache:
            self.audit_gate(rule, "allow", "tty-remembered", detail)
            return "allow"
        if self.approve_all:
            self.audit_gate(rule, "allow", "flag --approve-all", detail)
            return "allow"
        if self.auto_yes:
            self.audit_gate(rule, "deny", "flag --yes", detail)
            return "deny"
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGSTOP)
            except (ProcessLookupError, PermissionError):
                self.audit_gate(rule, "deny", "workload-gone", detail)
                return "deny"
        prompt_text = (
            f"[mantrap] {rule.description}: {detail} — allow once "
            "/ always / deny? [deny] "
        )
        try:
            with self._prompt_lock:
                answer = self.prompt_io(prompt_text)
        finally:
            if pgid is not None:
                try:
                    os.killpg(pgid, signal.SIGCONT)
                except OSError:
                    pass
        if answer is None:
            print(
                "[mantrap] no terminal for approval prompt; "
                f"denying: {detail}",
                file=sys.stderr,
            )
            self.audit_gate(rule, "deny", "no-tty", detail)
            return "deny"
        normalized = answer.strip().lower()
        if normalized in ("o", "once"):
            self.audit_gate(rule, "allow", "tty", detail)
            return "allow"
        if normalized in ("a", "always"):
            self._ask_cache[key] = "allow"
            self.audit_gate(rule, "allow", "tty", detail)
            return "allow"
        self.audit_gate(rule, "deny", "tty", detail)
        return "deny"

    def audit_gate(
        self, rule: GateRule, decision: str, decider: str, detail: str
    ) -> None:
        """Append one gate decision record; audit failure never breaks it.

        An audit failure is reported on stderr and swallowed so a
        logging problem cannot flip a deny into an allow (or crash an
        allow path that already decided).
        """
        from .audit import utc_now_iso

        record = {
            "v": 1,
            "ts": utc_now_iso(),
            "type": f"gate.{decision}",
            "rule": rule.id,
            "decision": decision,
            "decider": decider,
            "detail": detail,
        }
        try:
            self.audit_append(record)
        except Exception as exc:  # noqa: BLE001 - report, never break decision
            print(
                "[mantrap] gate audit append failed "
                f"({type(exc).__name__}); decision stands",
                file=sys.stderr,
            )
