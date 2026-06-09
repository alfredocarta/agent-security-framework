from __future__ import annotations

import argparse
import os
import select
import socket
import socketserver
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import TextIO
from urllib.parse import urlsplit

BUFFER_SIZE = 65536
DEFAULT_TIMEOUT = 10.0


def parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    items: list[str] = []
    for part in value.replace("\n", ",").split(","):
        item = part.strip().lower().rstrip(".")
        if item:
            items.append(item)
    return items


def parse_host_port(value: str, default_port: int) -> tuple[str, int]:
    if value.startswith("[") and "]" in value:
        host, _, rest = value[1:].partition("]")
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if ":" in value:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host.strip("[]"), int(port)
    return value.strip("[]"), default_port


def host_allowed(host: str, allowlist: list[str]) -> bool:
    normalized = host.lower().rstrip(".")
    for allowed in allowlist:
        allowed = allowed.lower().rstrip(".")
        if normalized == allowed or normalized.endswith(f".{allowed}"):
            return True
    return False


def parse_host_map(value: str | None) -> dict[str, tuple[str, int | None]]:
    mapping: dict[str, tuple[str, int | None]] = {}
    if not value:
        return mapping
    for entry in value.replace("\n", ",").split(","):
        item = entry.strip()
        if not item or "=" not in item:
            continue
        domain, target = item.split("=", 1)
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            continue
        if ":" in target:
            host, port = target.rsplit(":", 1)
            mapping[domain] = (host.strip(), int(port) if port.isdigit() else None)
        else:
            mapping[domain] = (target.strip(), None)
    return mapping


@dataclass
class ProxyDecision:
    allowed: bool
    host: str
    port: int
    reason: str


@dataclass
class EgressPolicy:
    allowlist: list[str]
    host_map: dict[str, tuple[str, int | None]] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "EgressPolicy":
        return cls(
            allowlist=parse_csv(os.environ.get("ASF_HERMES_NET_ALLOW")),
            host_map=parse_host_map(os.environ.get("ASF_EGRESS_HOST_MAP")),
        )

    def decide(self, host: str, port: int) -> ProxyDecision:
        normalized = host.lower().rstrip(".")
        if not self.allowlist:
            return ProxyDecision(False, normalized, port, "empty allowlist")
        if host_allowed(normalized, self.allowlist):
            return ProxyDecision(True, normalized, port, "domain allowed")
        return ProxyDecision(False, normalized, port, "domain not in allowlist")

    def connect_target(self, host: str, port: int) -> tuple[str, int]:
        mapped = self.host_map.get(host.lower().rstrip("."))
        if not mapped:
            return host, port
        mapped_host, mapped_port = mapped
        return mapped_host, mapped_port or port


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, *, policy: EgressPolicy, log_stream: TextIO | None = None):
        super().__init__(server_address, handler_class)
        self.policy = policy
        self.log_stream = log_stream or sys.stderr
        self.decisions: list[ProxyDecision] = []
        self._decision_lock = threading.Lock()

    def log_decision(self, decision: ProxyDecision, method: str) -> None:
        with self._decision_lock:
            self.decisions.append(decision)
        status = "ALLOW" if decision.allowed else "DENY"
        print(
            f"[ASF egress proxy] {status} method={method} host={decision.host} port={decision.port} reason={decision.reason}",
            file=self.log_stream,
            flush=True,
        )
        try:
            from audit import AUDITOR

            AUDITOR.log_event(
                "asf-egress-proxy",
                method,
                f"EGRESS_{status}",
                f"host={decision.host}; port={decision.port}; {decision.reason}",
            )
        except Exception:
            pass


class EgressProxyHandler(socketserver.StreamRequestHandler):
    timeout = DEFAULT_TIMEOUT

    def handle(self) -> None:
        request_line = self.rfile.readline(8192).decode("iso-8859-1", errors="replace").strip()
        if not request_line:
            return
        parts = request_line.split()
        if len(parts) < 3:
            self._send_error(400, "Bad Request")
            return
        method, target, version = parts[0].upper(), parts[1], parts[2]
        if method == "CONNECT":
            host, port = parse_host_port(target, 443)
            self._handle_connect(host, port)
            return
        self._handle_http(method, target, version)

    @property
    def policy(self) -> EgressPolicy:
        return self.server.policy  # type: ignore[attr-defined]

    def _read_headers(self) -> list[bytes]:
        headers: list[bytes] = []
        while True:
            line = self.rfile.readline(65536)
            if not line:
                break
            headers.append(line)
            if line in {b"\r\n", b"\n"}:
                break
        return headers

    def _host_from_headers(self, headers: list[bytes]) -> str | None:
        for raw in headers:
            if raw.lower().startswith(b"host:"):
                return raw.decode("iso-8859-1", errors="replace").split(":", 1)[1].strip()
        return None

    def _handle_connect(self, host: str, port: int) -> None:
        self._read_headers()
        decision = self.policy.decide(host, port)
        self.server.log_decision(decision, "CONNECT")  # type: ignore[attr-defined]
        if not decision.allowed:
            self._send_error(403, f"ASF egress denied: {decision.reason}")
            return
        try:
            target_host, target_port = self.policy.connect_target(host, port)
            upstream = socket.create_connection((target_host, target_port), timeout=DEFAULT_TIMEOUT)
        except OSError as exc:
            self._send_error(502, f"Bad Gateway: {exc}")
            return
        with upstream:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._tunnel(upstream)

    def _handle_http(self, method: str, target: str, version: str) -> None:
        headers = self._read_headers()
        parsed = urlsplit(target)
        if parsed.scheme and parsed.netloc:
            host, port = parse_host_port(parsed.netloc, 80 if parsed.scheme == "http" else 443)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        else:
            host_header = self._host_from_headers(headers)
            if not host_header:
                self._send_error(400, "Missing Host header")
                return
            host, port = parse_host_port(host_header, 80)
            path = target or "/"
        decision = self.policy.decide(host, port)
        self.server.log_decision(decision, method)  # type: ignore[attr-defined]
        if not decision.allowed:
            self._send_error(403, f"ASF egress denied: {decision.reason}")
            return
        try:
            target_host, target_port = self.policy.connect_target(host, port)
            upstream = socket.create_connection((target_host, target_port), timeout=DEFAULT_TIMEOUT)
        except OSError as exc:
            self._send_error(502, f"Bad Gateway: {exc}")
            return
        with upstream:
            upstream_file = upstream.makefile("rwb", buffering=0)
            upstream_file.write(f"{method} {path} {version}\r\n".encode("iso-8859-1"))
            for header in headers:
                if header.lower().startswith(b"proxy-connection:"):
                    continue
                upstream_file.write(header)
            while True:
                data = upstream.recv(BUFFER_SIZE)
                if not data:
                    break
                self.wfile.write(data)

    def _tunnel(self, upstream: socket.socket) -> None:
        sockets = [self.connection, upstream]
        while True:
            readable, _, errored = select.select(sockets, [], sockets, DEFAULT_TIMEOUT)
            if errored or not readable:
                break
            for sock in readable:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    return
                other = upstream if sock is self.connection else self.connection
                other.sendall(data)

    def _send_error(self, code: int, message: str) -> None:
        body = f"{message}\n".encode("utf-8")
        self.wfile.write(
            f"HTTP/1.1 {code} {message}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode(
                "iso-8859-1", errors="replace"
            )
            + body
        )


def serve(host: str, port: int, policy: EgressPolicy, *, log_stream: TextIO | None = None) -> ThreadedTCPServer:
    server = ThreadedTCPServer((host, port), EgressProxyHandler, policy=policy, log_stream=log_stream)
    thread = threading.Thread(target=server.serve_forever, name="asf-egress-proxy", daemon=True)
    thread.start()
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASF local egress proxy with domain allowlist")
    parser.add_argument("--host", default=os.environ.get("ASF_EGRESS_PROXY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ASF_EGRESS_PROXY_PORT", "0")))
    parser.add_argument("--allow", default=os.environ.get("ASF_HERMES_NET_ALLOW", ""))
    parser.add_argument("--host-map", default=os.environ.get("ASF_EGRESS_HOST_MAP", ""))
    args = parser.parse_args(argv)

    policy = EgressPolicy(parse_csv(args.allow), parse_host_map(args.host_map))
    server = serve(args.host, args.port, policy)
    actual_port = server.server_address[1]
    print(f"[ASF egress proxy] listening on {args.host}:{actual_port}", file=sys.stderr, flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
