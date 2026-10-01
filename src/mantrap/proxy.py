"""Filtering egress proxy (host side) for `network.mode: allowlist`.

Speaks the HTTP forward-proxy protocol (absolute-URI requests and
CONNECT) on both a TCP listener (127.0.0.1, ephemeral port) and a
unix socket. Only forwards to allowlisted destinations; everything
else gets 403 plus an audit record.

Decision order per request (allowlist BEFORE any DNS or upstream
contact, so denied domains are never even resolved):

  1. Parse the request (CONNECT host:port, or absolute-URI
     http://host[:port]/path when plain HTTP is enabled).
     Unparseable/origin-form requests get 400 and are not audited
     (nothing to attribute them to).
  2. Allowlist match: exact or `*.suffix` (suffix matches real
     subdomains only, never the bare domain), case-insensitive,
     trailing-dot stripped, IDNA-normalized. IP literals match
     only when the literal itself is listed. Miss -> 403
     (reason not_allowlisted).
  3. CONNECT port must be in allow_ports, else 403
     (reason port_not_allowed).
  4. Plain HTTP requires allow_plain_http, else 403
     (reason plain_http_disabled).
  5. Name resolution on the host side (unless dns is "off", in
     which case hostnames are refused with 403 reason
     dns_disabled and only listed IP literals work). Unresolvable
     names get 403 (reason resolve_failed).
  6. Private-IP guard: any resolved/special IP (loopback,
     private, link-local, multicast, reserved, unspecified) is
     refused with 403 (reason private_ip) unless
     allow_private_ips is set. The guard also applies to listed
     IP literals. This blocks SSRF to e.g. 169.254.169.254 by
     default.
  7. Forward: CONNECT splices a tunnel after `200 Connection
     established`; plain HTTP is re-emitted origin-form with
     hop-by-hop headers stripped, then the response is spliced
     back until EOF (60s idle timeout).

Parent-proxy chaining: when the host sets HTTPS_PROXY (or
lowercase https_proxy), upstream TCP goes to the parent instead:
CONNECT is re-issued to the parent, plain HTTP is forwarded with
the absolute URI intact. Parent-proxy authentication is out of
scope (credentials in the parent URL are ignored, never logged).

Audit: every attributable request appends one record via the
given callback: {"v": 1, "ts", "type": "net.allow"/"net.deny",
"domain", "port", "scheme": "http"/"connect", "decision":
"allow"/"deny", "reason"}. A failing audit callback never crashes
the proxy (the failure goes to stderr).

Robustness: one daemon thread per connection; malformed input
closes the connection without affecting others. Bodies are not
parsed: after headers, bytes splice in both directions until EOF,
so each proxied connection carries a single request/response
exchange and then closes.

Residual risk: DNS is re-resolved per request on the host side,
so a name whose records change mid-session (DNS rebinding) is
checked against the records seen at request time only.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .audit import append_record, utc_now_iso

HEADER_LIMIT = 64 * 1024
READ_TIMEOUT_S = 10.0
CONNECT_TIMEOUT_S = 10.0
IDLE_TIMEOUT_S = 60.0

RELAY_LISTEN = "127.0.0.1:18080"

HOP_BY_HOP = frozenset(
    {
        "proxy-connection",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "te",
        "trailer",
        "upgrade",
    }
)


class _HttpError(Exception):
    """A request-level failure with an HTTP status, no audit record."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class _QuietClose(Exception):
    """Client went away before sending anything; just close."""


def normalize_host(raw: str) -> str:
    """Lowercase, strip one trailing dot, IDNA-encode to ASCII."""
    host = raw.strip()
    if host.endswith("."):
        host = host[:-1]
    host = host.lower()
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def strip_brackets(host: str) -> str:
    host = host.strip()
    if len(host) >= 2 and host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def parse_ip(text: str):
    """Return an ipaddress object, or None when not a literal."""
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def domain_allowed(host: str, allow_domains: list[str]) -> bool:
    """True when host matches the allowlist (exact or *.suffix).

    Suffix entries match real subdomains only, never the bare
    domain. IP literals match only when the literal itself is
    listed (compared as addresses, so textual forms agree).
    """
    bare = strip_brackets(host)
    normalized = normalize_host(bare)
    literal = parse_ip(normalized)
    if literal is not None:
        for entry in allow_domains:
            candidate = strip_brackets(entry)
            if candidate == bare:
                return True
            other = parse_ip(normalize_host(candidate))
            if other is not None and other == literal:
                return True
        return False
    for entry in allow_domains:
        text = entry.strip()
        if text.startswith("*."):
            suffix = normalize_host(text[2:])
            if normalized != suffix and normalized.endswith("." + suffix):
                return True
        elif normalize_host(text) == normalized:
            return True
    return False


def is_special_ip(address) -> bool:
    """True for non-public IPs: loopback, private, link-local,
    multicast, reserved, or unspecified."""
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def split_host_port(target: str) -> tuple[str, int]:
    """Split a CONNECT target into (host, port); 400 on bad input."""
    if target.startswith("["):
        end = target.find("]")
        if end == -1 or not target[end + 1 :].startswith(":"):
            raise _HttpError(400, "bad CONNECT target")
        host = target[1:end]
        port_text = target[end + 2 :]
    elif ":" not in target:
        raise _HttpError(400, "bad CONNECT target")
    else:
        host, _, port_text = target.rpartition(":")
    if not host:
        raise _HttpError(400, "bad CONNECT target")
    try:
        port = int(port_text)
    except ValueError:
        raise _HttpError(400, "bad CONNECT port") from None
    if not 1 <= port <= 65535:
        raise _HttpError(400, "bad CONNECT port")
    return host, port


def parse_absolute_uri(target: str) -> tuple[str, int, str]:
    """Split an absolute-URI target into (host, port, origin-form path)."""
    try:
        parts = urlsplit(target)
    except ValueError:
        raise _HttpError(400, "bad request target") from None
    if parts.scheme != "http" or not parts.hostname:
        raise _HttpError(400, "bad request target")
    try:
        port = parts.port or 80
    except ValueError:
        raise _HttpError(400, "bad request port") from None
    if not 1 <= port <= 65535:
        raise _HttpError(400, "bad request port")
    origin = parts.path or "/"
    if parts.query:
        origin += "?" + parts.query
    return parts.hostname, port, origin


def parse_request(head: bytes) -> tuple[str, str, list[tuple[str, str]]]:
    """Split a header block into (METHOD, target, [(name, value)])."""
    try:
        text = head.decode("latin-1")
    except UnicodeDecodeError:
        raise _HttpError(400, "bad request encoding") from None
    lines = text.split("\r\n")
    words = lines[0].split()
    if len(words) != 3:
        raise _HttpError(400, "bad request line")
    method, target, _version = words
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            continue
        headers.append((name.strip(), value.strip()))
    return method.upper(), target, headers


def read_head(conn: socket.socket) -> bytes:
    """Read until the end of the header block (or 408/close)."""
    conn.settimeout(READ_TIMEOUT_S)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            if len(buf) > HEADER_LIMIT:
                raise _HttpError(408, "header too large")
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
    except TimeoutError:
        raise _HttpError(408, "read timeout") from None
    except OSError:
        raise _QuietClose from None
    if not buf:
        raise _QuietClose
    if b"\r\n\r\n" not in buf:
        raise _HttpError(400, "incomplete request")
    return buf.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"


def parent_proxy_from_env() -> tuple[str, int] | None:
    """(host, port) of the host's upstream proxy, if configured."""
    for name in ("HTTPS_PROXY", "https_proxy"):
        value = os.environ.get(name, "").strip()
        if not value:
            continue
        try:
            parts = urlsplit(value if "://" in value else "http://" + value)
        except ValueError:
            continue
        if not parts.hostname:
            continue
        try:
            port = parts.port or 80
        except ValueError:
            continue
        return parts.hostname, port
    return None


def splice(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes both ways until EOF (60s idle timeout per read)."""

    def forward(src: socket.socket, dst: socket.socket) -> None:
        try:
            src.settimeout(IDLE_TIMEOUT_S)
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    first = threading.Thread(target=forward, args=(a, b), daemon=True)
    second = threading.Thread(target=forward, args=(b, a), daemon=True)
    first.start()
    second.start()
    first.join(IDLE_TIMEOUT_S + 5)
    second.join(IDLE_TIMEOUT_S + 5)


@dataclass
class ProxyHandle:
    """A running proxy instance."""

    tcp_port: int
    sock_path: str
    _stop_event: threading.Event = field(repr=False)
    _listeners: list = field(default_factory=list, repr=False)
    _accept_threads: list = field(default_factory=list, repr=False)

    def stop(self) -> None:
        self._stop_event.set()
        for listener in self._listeners:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                listener.close()
            except OSError:
                pass
        for thread in self._accept_threads:
            thread.join(timeout=2.0)
        # Don't leave a stale socket behind: a leftover path with no
        # listener would only confuse the next run's diagnostics.
        try:
            os.unlink(self.sock_path)
        except OSError:
            pass


class FilteringProxy:
    """The filtering engine; one instance serves all connections."""

    def __init__(self, net_config, audit_append=None):
        self.allow_domains = list(net_config.allow_domains)
        self.allow_plain_http = net_config.allow_plain_http
        self.allow_ports = list(net_config.allow_ports)
        self.dns = net_config.dns
        self.allow_private_ips = net_config.allow_private_ips
        self.audit_append = audit_append or append_record

    def audit(self, *, type: str, domain: str, port: int,
              scheme: str, decision: str, reason: str) -> None:
        try:
            self.audit_append(
                {
                    "v": 1,
                    "ts": utc_now_iso(),
                    "type": type,
                    "domain": domain,
                    "port": port,
                    "scheme": scheme,
                    "decision": decision,
                    "reason": reason,
                }
            )
        except Exception as exc:  # noqa: BLE001 - never crash on audit
            print(f"proxy: audit append failed: {exc}")

    def deny(self, conn: socket.socket, *, domain: str, port: int,
             scheme: str, reason: str) -> None:
        self.audit(
            type="net.deny", domain=domain, port=port,
            scheme=scheme, decision="deny", reason=reason,
        )
        body = f"forbidden: {reason}\n".encode()
        try:
            conn.sendall(
                b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
        except OSError:
            pass

    def resolve(self, host: str) -> tuple[list[str] | None, str | None]:
        """Resolve host to IP strings; (None, reason) when refused."""
        bare = strip_brackets(host)
        literal = parse_ip(normalize_host(bare))
        if literal is not None:
            return [str(literal)], None
        if self.dns == "off":
            return None, "dns_disabled"
        try:
            infos = socket.getaddrinfo(
                normalize_host(bare), None, type=socket.SOCK_STREAM
            )
        except socket.gaierror:
            return None, "resolve_failed"
        ips = sorted({str(info[4][0]) for info in infos})
        if not ips:
            return None, "resolve_failed"
        return ips, None

    def guard(self, ips: list[str]) -> str | None:
        """Private-IP check; returns the deny reason or None."""
        if self.allow_private_ips:
            return None
        for text in ips:
            address = parse_ip(text)
            if address is None or is_special_ip(address):
                return "private_ip"
        return None

    def connect_upstream(
        self, ips: list[str], port: int
    ) -> socket.socket | None:
        for ip in ips:
            try:
                return socket.create_connection(
                    (ip, port), timeout=CONNECT_TIMEOUT_S
                )
            except OSError:
                continue
        return None

    @staticmethod
    def send_error(conn: socket.socket, status: int, reason: str) -> None:
        phrases = {400: "Bad Request", 408: "Request Timeout",
                   502: "Bad Gateway"}
        phrase = phrases.get(status, "Error")
        body = f"{status} {phrase}: {reason}\n".encode()
        try:
            conn.sendall(
                f"HTTP/1.1 {status} {phrase}\r\n".encode()
                + b"Content-Type: text/plain\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
        except OSError:
            pass

    def handle_connect(
        self, conn: socket.socket, host: str, port: int
    ) -> None:
        if not domain_allowed(host, self.allow_domains):
            self.deny(conn, domain=strip_brackets(host), port=port,
                      scheme="connect", reason="not_allowlisted")
            return
        if port not in self.allow_ports:
            self.deny(conn, domain=strip_brackets(host), port=port,
                      scheme="connect", reason="port_not_allowed")
            return
        ips, error = self.resolve(host)
        if ips is None:
            assert error is not None
            self.deny(conn, domain=strip_brackets(host), port=port,
                      scheme="connect", reason=error)
            return
        blocked = self.guard(ips)
        if blocked is not None:
            self.deny(conn, domain=strip_brackets(host), port=port,
                      scheme="connect", reason=blocked)
            return
        parent = parent_proxy_from_env()
        if parent is not None:
            self.chain_connect(conn, parent, host, port)
            return
        upstream = self.connect_upstream(ips, port)
        if upstream is None:
            self.audit(type="net.allow", domain=strip_brackets(host),
                       port=port, scheme="connect", decision="allow",
                       reason="upstream_failed")
            self.send_error(conn, 502, "upstream connect failed")
            return
        try:
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except OSError:
            upstream.close()
            return
        self.audit(type="net.allow", domain=strip_brackets(host),
                   port=port, scheme="connect", decision="allow",
                   reason="ok")
        try:
            splice(conn, upstream)
        finally:
            upstream.close()

    def chain_connect(self, conn: socket.socket,
                      parent: tuple[str, int], host: str, port: int) -> None:
        domain = strip_brackets(host)
        try:
            upstream = socket.create_connection(
                parent, timeout=CONNECT_TIMEOUT_S
            )
        except OSError:
            self.audit(type="net.allow", domain=domain, port=port,
                       scheme="connect", decision="allow",
                       reason="upstream_failed")
            self.send_error(conn, 502, "parent proxy unreachable")
            return
        try:
            upstream.sendall(
                f"CONNECT {domain}:{port} HTTP/1.1\r\n"
                f"Host: {domain}:{port}\r\n"
                "Connection: close\r\n\r\n".encode()
            )
            head = read_head(upstream)
            status = head.decode("latin-1").split("\r\n", 1)[0]
            words = status.split()
            if len(words) < 2 or words[1] != "200":
                raise _HttpError(502, "parent proxy refused CONNECT")
        except (TimeoutError, _HttpError, OSError) as exc:
            reason = getattr(exc, "reason", None) or "upstream_failed"
            self.audit(type="net.allow", domain=domain, port=port,
                       scheme="connect", decision="allow", reason=reason)
            self.send_error(conn, 502, str(reason))
            upstream.close()
            return
        try:
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except OSError:
            upstream.close()
            return
        self.audit(type="net.allow", domain=domain, port=port,
                   scheme="connect", decision="allow", reason="ok")
        try:
            splice(conn, upstream)
        finally:
            upstream.close()

    def handle_plain(self, conn: socket.socket, method: str,
                     target: str,
                     headers: list[tuple[str, str]]) -> None:
        host, port, origin = parse_absolute_uri(target)
        domain = strip_brackets(host)
        if not domain_allowed(host, self.allow_domains):
            self.deny(conn, domain=domain, port=port,
                      scheme="http", reason="not_allowlisted")
            return
        if not self.allow_plain_http:
            self.deny(conn, domain=domain, port=port,
                      scheme="http", reason="plain_http_disabled")
            return
        ips, error = self.resolve(host)
        if ips is None:
            assert error is not None
            self.deny(conn, domain=domain, port=port,
                      scheme="http", reason=error)
            return
        blocked = self.guard(ips)
        if blocked is not None:
            self.deny(conn, domain=domain, port=port,
                      scheme="http", reason=blocked)
            return
        parent = parent_proxy_from_env()
        if parent is not None:
            self.chain_plain(conn, parent, method, target,
                             headers, domain, port)
            return
        upstream = self.connect_upstream(ips, port)
        if upstream is None:
            self.audit(type="net.allow", domain=domain, port=port,
                       scheme="http", decision="allow",
                       reason="upstream_failed")
            self.send_error(conn, 502, "upstream connect failed")
            return
        lines = [f"{method} {origin} HTTP/1.1"]
        for name, value in headers:
            if name.lower() not in HOP_BY_HOP:
                lines.append(f"{name}: {value}")
        lines.append("Connection: close")
        try:
            upstream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode(
                "latin-1"))
        except OSError:
            upstream.close()
            self.audit(type="net.allow", domain=domain, port=port,
                       scheme="http", decision="allow",
                       reason="upstream_failed")
            self.send_error(conn, 502, "upstream write failed")
            return
        self.audit(type="net.allow", domain=domain, port=port,
                   scheme="http", decision="allow", reason="ok")
        try:
            splice(conn, upstream)
        finally:
            upstream.close()

    def chain_plain(self, conn: socket.socket, parent: tuple[str, int],
                    method: str, target: str,
                    headers: list[tuple[str, str]],
                    domain: str, port: int) -> None:
        try:
            upstream = socket.create_connection(
                parent, timeout=CONNECT_TIMEOUT_S
            )
        except OSError:
            self.audit(type="net.allow", domain=domain, port=port,
                       scheme="http", decision="allow",
                       reason="upstream_failed")
            self.send_error(conn, 502, "parent proxy unreachable")
            return
        lines = [f"{method} {target} HTTP/1.1"]
        for name, value in headers:
            if name.lower() not in HOP_BY_HOP:
                lines.append(f"{name}: {value}")
        lines.append("Connection: close")
        try:
            upstream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode(
                "latin-1"))
        except OSError:
            upstream.close()
            self.audit(type="net.allow", domain=domain, port=port,
                       scheme="http", decision="allow",
                       reason="upstream_failed")
            self.send_error(conn, 502, "parent write failed")
            return
        self.audit(type="net.allow", domain=domain, port=port,
                   scheme="http", decision="allow", reason="ok")
        try:
            splice(conn, upstream)
        finally:
            upstream.close()

    def handle_one(self, conn: socket.socket) -> None:
        try:
            head = read_head(conn)
            method, target, headers = parse_request(head)
            if method == "CONNECT":
                host, port = split_host_port(target)
                self.handle_connect(conn, host, port)
            elif target.startswith("http://"):
                self.handle_plain(conn, method, target, headers)
            else:
                raise _HttpError(400, "unsupported request form")
        except _QuietClose:
            pass
        except _HttpError as exc:
            self.send_error(conn, exc.status, exc.reason)
        except Exception as exc:  # noqa: BLE001 - never crash on input
            print(f"proxy: connection error: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass


def start_proxy(net_config, data_dir, audit_append=None) -> ProxyHandle:
    """Start the filtering proxy; returns a handle with .tcp_port/.stop().

    Listens on 127.0.0.1 (ephemeral TCP port) and on
    <data_dir>/proxy.sock (unix socket, data dir created mode 700
    when missing). net_config carries mode, allow_domains,
    allow_plain_http, allow_ports, dns, allow_private_ips.
    """
    if getattr(net_config, "mode", "allowlist") != "allowlist":
        raise ValueError(
            "filtering proxy requires network.mode 'allowlist'"
        )
    directory = Path(data_dir)
    if not directory.exists():
        directory.mkdir(parents=True, mode=0o700)
        os.chmod(directory, 0o700)
    sock_path = directory / "proxy.sock"
    try:
        sock_path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass

    engine = FilteringProxy(net_config, audit_append=audit_append)
    stop_event = threading.Event()

    tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_listener.bind(("127.0.0.1", 0))
    tcp_listener.listen(100)
    tcp_port = tcp_listener.getsockname()[1]

    unix_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unix_listener.bind(str(sock_path))
    try:
        os.chmod(sock_path, 0o600)
    except OSError:
        pass
    unix_listener.listen(100)

    def accept_loop(listener: socket.socket) -> None:
        listener.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _peer = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            thread = threading.Thread(
                target=engine.handle_one, args=(conn,), daemon=True
            )
            thread.start()

    threads = [
        threading.Thread(target=accept_loop, args=(listener,), daemon=True)
        for listener in (tcp_listener, unix_listener)
    ]
    for thread in threads:
        thread.start()

    return ProxyHandle(
        tcp_port=tcp_port,
        sock_path=str(sock_path),
        _stop_event=stop_event,
        _listeners=[tcp_listener, unix_listener],
        _accept_threads=threads,
    )
