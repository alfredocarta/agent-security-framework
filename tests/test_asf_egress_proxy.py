import http.server
import shutil
import socket
import socketserver
import subprocess
import threading
from pathlib import Path

import pytest

from wrapper.asf_egress_proxy import EgressPolicy, host_allowed, parse_csv, parse_host_map, serve


class _StaticHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"asf-approved-local-server"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def _start_http_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), _StaticHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_proxy_allowlist_matches_exact_and_subdomain():
    allow = parse_csv("example.com, allowed.test")

    assert host_allowed("example.com", allow)
    assert host_allowed("api.example.com", allow)
    assert host_allowed("allowed.test", allow)
    assert not host_allowed("evil.test", allow)
    assert not host_allowed("badexample.com", allow)


def test_proxy_policy_allows_and_denies_connect_targets():
    policy = EgressPolicy(parse_csv("approved.test"), parse_host_map("approved.test=127.0.0.1:8080"))

    approved = policy.decide("api.approved.test", 443)
    denied = policy.decide("evil.test", 443)

    assert approved.allowed is True
    assert approved.reason == "domain allowed"
    assert denied.allowed is False
    assert denied.reason == "domain not in allowlist"


def test_proxy_http_request_allowed_and_denied_without_external_network():
    http_server = _start_http_server()
    http_port = int(http_server.server_address[1])
    proxy = serve(
        "127.0.0.1",
        0,
        EgressPolicy(
            parse_csv("approved.test"),
            parse_host_map(f"approved.test=127.0.0.1:{http_port}"),
        ),
    )
    proxy_port = int(proxy.server_address[1])
    try:
        allowed = subprocess.run(
            [
                "curl",
                "-sS",
                "--max-time",
                "3",
                "-x",
                f"http://127.0.0.1:{proxy_port}",
                "http://approved.test/",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        denied = subprocess.run(
            [
                "curl",
                "-sS",
                "--max-time",
                "3",
                "--fail",
                "-x",
                f"http://127.0.0.1:{proxy_port}",
                "http://evil.test/",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        proxy.shutdown()
        proxy.server_close()
        http_server.shutdown()
        http_server.server_close()

    assert allowed.returncode == 0
    assert "asf-approved-local-server" in allowed.stdout
    assert denied.returncode != 0
    assert any(decision.allowed for decision in proxy.decisions)
    assert any(not decision.allowed for decision in proxy.decisions)


def test_proxy_connect_request_allowed_and_denied_without_external_network():
    http_server = _start_http_server()
    http_port = int(http_server.server_address[1])
    proxy = serve(
        "127.0.0.1",
        0,
        EgressPolicy(
            parse_csv("approved.test"),
            parse_host_map(f"approved.test=127.0.0.1:{http_port}"),
        ),
    )
    proxy_port = int(proxy.server_address[1])
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as sock:
            sock.sendall(b"CONNECT approved.test:443 HTTP/1.1\r\nHost: approved.test:443\r\n\r\n")
            allowed = sock.recv(4096)
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as sock:
            sock.sendall(b"CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n")
            denied = sock.recv(4096)
    finally:
        proxy.shutdown()
        proxy.server_close()
        http_server.shutdown()
        http_server.server_close()

    assert b"200 Connection Established" in allowed
    assert b"403" in denied
    assert any(decision.allowed and decision.host == "approved.test" for decision in proxy.decisions)
    assert any(not decision.allowed and decision.host == "evil.test" for decision in proxy.decisions)


@pytest.mark.skipif(not shutil.which("sandbox-exec"), reason="sandbox-exec is not available")
@pytest.mark.skipif(not shutil.which("curl"), reason="curl is not available")
def test_sandbox_allows_only_proxy_network_for_approved_domains(tmp_path):
    http_server = _start_http_server()
    http_port = int(http_server.server_address[1])
    proxy = serve(
        "127.0.0.1",
        0,
        EgressPolicy(
            parse_csv("approved.test"),
            parse_host_map(f"approved.test=127.0.0.1:{http_port}"),
        ),
    )
    proxy_port = int(proxy.server_address[1])
    profile = Path(__file__).resolve().parents[1] / "wrapper" / "asf_sandbox.sb"
    base = [
        "sandbox-exec",
        "-D",
        f"WORKDIR={tmp_path}",
        "-D",
        f"PROXY_PORT={proxy_port}",
        "-f",
        str(profile),
    ]
    try:
        via_proxy = subprocess.run(
            [
                *base,
                "curl",
                "-sS",
                "--max-time",
                "3",
                "-x",
                f"http://127.0.0.1:{proxy_port}",
                "http://approved.test/",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        denied_domain = subprocess.run(
            [
                *base,
                "curl",
                "-sS",
                "--max-time",
                "3",
                "--fail",
                "-x",
                f"http://127.0.0.1:{proxy_port}",
                "http://evil.test/",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        direct = subprocess.run(
            [
                *base,
                "curl",
                "-sS",
                "--max-time",
                "3",
                "--noproxy",
                "*",
                f"http://127.0.0.1:{http_port}/",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        proxy.shutdown()
        proxy.server_close()
        http_server.shutdown()
        http_server.server_close()

    assert via_proxy.returncode == 0, via_proxy.stderr
    assert "asf-approved-local-server" in via_proxy.stdout
    assert denied_domain.returncode != 0
    assert direct.returncode != 0
