"""In-sandbox TCP relay: sandbox loopback -> host filtering proxy.

Runs inside the sandbox (bind-mounted read-only at
/run/mantrap/relay.py). Listens on 127.0.0.1:PORT and splices each
accepted TCP connection through to the host proxy over the
bind-mounted unix socket.

Daemonize-then-exec: the listener is bound first (a bind failure
exits nonzero before the workload ever starts), the proxy socket
is probed once up front (missing socket exits nonzero), then a
double-forked daemon serves the relay while the original process
execs the workload and becomes the sandbox init. Consequences:

- relay can't bind / proxy socket missing -> workload never starts.
- workload exits (pidns init) -> the kernel kills the daemon.
- daemon killed first -> 127.0.0.1:PORT refuses -> the workload's
  network access dies with it. Fail-closed in every direction.

Self-contained: only the stdlib, no mantrap imports (just this
file is mounted into the sandbox).
"""

from __future__ import annotations

import os
import socket
import sys
import threading


def _forward(src: socket.socket, dst: socket.socket) -> None:
    try:
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


def _splice(client: socket.socket, upstream: socket.socket) -> None:
    first = threading.Thread(target=_forward, args=(client, upstream))
    second = threading.Thread(target=_forward, args=(upstream, client))
    first.daemon = True
    second.daemon = True
    first.start()
    second.start()
    first.join()
    second.join()


def _handle(client: socket.socket, sock_path: str) -> None:
    try:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.connect(sock_path)
    except OSError:
        try:
            client.close()
        except OSError:
            pass
        return
    try:
        _splice(client, upstream)
    finally:
        for conn in (client, upstream):
            try:
                conn.close()
            except OSError:
                pass


def _serve(listener: socket.socket, sock_path: str) -> None:
    while True:
        try:
            client, _peer = listener.accept()
        except OSError:
            return
        thread = threading.Thread(target=_handle, args=(client, sock_path))
        thread.daemon = True
        thread.start()


def parse(argv: list[str]) -> tuple[str, int, list[str]] | None:
    """Parse: relay.py --sock PATH --listen-port PORT -- workload..."""
    sock: str | None = None
    port: str | None = None
    rest = list(argv)
    workload: list[str] = []
    if "--" in rest:
        cut = rest.index("--")
        workload = rest[cut + 1 :]
        rest = rest[:cut]
    pairs = [rest[i : i + 2] for i in range(0, len(rest), 2)]
    for pair in pairs:
        if len(pair) != 2:
            return None
        key, value = pair
        if key == "--sock":
            sock = value
        elif key == "--listen-port":
            port = value
        else:
            return None
    if sock is None or port is None or not workload:
        return None
    try:
        port_no = int(port)
    except ValueError:
        return None
    if not 1 <= port_no <= 65535:
        return None
    return sock, port_no, workload


def main(argv: list[str]) -> int:
    parsed = parse(argv)
    if parsed is None:
        print(
            "usage: relay.py --sock PATH --listen-port PORT -- <workload...>",
            file=sys.stderr,
        )
        return 2
    sock_path, port_no, workload = parsed
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.connect(sock_path)
        probe.close()
    except OSError as exc:
        print(f"relay: cannot reach proxy socket {sock_path}: {exc}",
              file=sys.stderr)
        return 1
    try:
        listener = socket.create_server(
            ("127.0.0.1", port_no), backlog=64)
    except OSError as exc:
        print(f"relay: cannot listen on 127.0.0.1:{port_no}: {exc}",
              file=sys.stderr)
        return 1
    pid = os.fork()
    if pid != 0:
        _, status = os.waitpid(pid, 0)
        listener.close()
        if status != 0:
            return 1
        try:
            os.execvp(workload[0], workload)
        except OSError as exc:
            print(f"relay: cannot exec {workload[0]}: {exc}",
                  file=sys.stderr)
            return 127
        return 127
    try:
        os.setsid()
        second = os.fork()
        if second != 0:
            os._exit(0)
        devnull = os.open("/dev/null", os.O_RDWR)
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        _serve(listener, sock_path)
    finally:
        os._exit(0)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
