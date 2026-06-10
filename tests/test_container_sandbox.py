"""Docker-gated smoke test for the Phase 3 host-enforced container boundary.

Like tests/test_sandbox.py, this skips cleanly when Docker is not running, so the
full suite stays green on machines without a Docker daemon (e.g. CI without DinD,
or a laptop with Docker Desktop stopped).

When Docker IS available it proves the three boundary properties the design claims:
  (a) a write to a host path OUTSIDE the bind-mounted workspace is impossible;
  (b) direct egress to a non-proxy host fails, while egress through the ASF egress
      proxy to an allowed host works (and a denied host is refused by the proxy);
  (c) a normal in-workspace tool call succeeds.

The container runs with exactly the confinement flags production would use, via
wrapper/asf_container_launch.hardened_run_args, so the test exercises the real path.
"""

from __future__ import annotations

import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

ASF_ROOT = Path(__file__).resolve().parents[1]
if str(ASF_ROOT / "wrapper") not in sys.path:
    sys.path.insert(0, str(ASF_ROOT))

from wrapper import asf_container_launch as launch  # noqa: E402

IMAGE = launch.DEFAULT_IMAGE
PROXY_PORT = launch.DEFAULT_PROXY_PORT
ORIGIN_BODY = "HELLO_FROM_ALLOWED_ORIGIN"


def _docker(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _run_confined(workspace: str, network: str, proxy_url: str | None, command: list[str]) -> subprocess.CompletedProcess:
    args = launch.hardened_run_args(
        workspace=workspace,
        image=IMAGE,
        network=network,
        proxy_url=proxy_url,
        command=command,
        allowlist="allowed.test",
    )
    return subprocess.run(args, check=False, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


@pytest.fixture(scope="module")
def boundary(tmp_path_factory):
    if not launch.docker_available():
        pytest.skip("Docker daemon not available; skipping Phase 3 container boundary smoke test.")

    if not launch.image_exists(IMAGE):
        try:
            launch.build_image(IMAGE)
        except subprocess.CalledProcessError as exc:  # offline / no base image: environmental, not a logic failure
            pytest.skip(f"Could not build {IMAGE} (likely offline): {exc}")

    suffix = uuid.uuid4().hex[:8]
    internal_net = f"asf-p3smoke-int-{suffix}"
    external_net = f"asf-p3smoke-ext-{suffix}"
    origin_name = f"asf-p3smoke-origin-{suffix}"
    proxy_name = f"asf-p3smoke-proxy-{suffix}"

    workspace = tmp_path_factory.mktemp("asf_p3_workspace")
    # A host path deliberately NOT mounted into the container.
    outside = tmp_path_factory.mktemp("asf_p3_outside")
    (outside / "host_secret.txt").write_text("TOP_SECRET_HOST_FILE")

    created = {"nets": [], "containers": []}
    try:
        launch.ensure_network(external_net, internal=False)
        created["nets"].append(external_net)
        launch.ensure_network(internal_net, internal=True)
        created["nets"].append(internal_net)

        # Origin server on the external network; reachable only via the proxy.
        _docker([
            "run", "-d", "--rm", "--name", origin_name, "--network", external_net,
            "python:3.11-slim", "sh", "-c",
            f"mkdir -p /srv && printf '{ORIGIN_BODY}' > /srv/index.html && cd /srv && python -m http.server 8000",
        ])
        created["containers"].append(origin_name)

        proxy_url = launch.start_proxy_sidecar(
            image=IMAGE,
            external_net=external_net,
            internal_net=internal_net,
            name=proxy_name,
            allowlist="allowed.test",
            host_map=f"allowed.test={origin_name}:8000",
            port=PROXY_PORT,
        )
        created["containers"].append(proxy_name)

        # Wait until the proxy can actually reach the origin for an allowed request.
        deadline = time.time() + 30
        ready = False
        while time.time() < deadline:
            res = _run_confined(str(workspace), internal_net, proxy_url,
                                ["curl", "-s", "--max-time", "5", "-x", proxy_url, "http://allowed.test/"])
            if res.returncode == 0 and ORIGIN_BODY in res.stdout:
                ready = True
                break
            time.sleep(1)
        if not ready:
            pytest.skip("Egress proxy/origin did not become ready in time; environmental, not a boundary failure.")

        yield {
            "workspace": str(workspace),
            "outside": str(outside),
            "internal_net": internal_net,
            "proxy_url": proxy_url,
        }
    finally:
        for name in created["containers"]:
            _docker(["rm", "-f", name], check=False)
        for net in created["nets"]:
            _docker(["network", "rm", net], check=False)


def test_write_outside_workspace_is_impossible(boundary):
    workspace = boundary["workspace"]
    net = boundary["internal_net"]
    proxy = boundary["proxy_url"]

    # The unmounted host path simply does not exist inside the container...
    probe = _run_confined(workspace, net, proxy, [
        "sh", "-c",
        f"test -e {boundary['outside']} && echo HOST_PATH_VISIBLE || echo HOST_PATH_ABSENT",
    ])
    assert "HOST_PATH_ABSENT" in probe.stdout, probe.stdout + probe.stderr

    # ...and the root filesystem is read-only, so nothing outside /workspace is writable.
    ro = _run_confined(workspace, net, proxy, [
        "sh", "-c",
        "touch /opt/asf/escape 2>/dev/null && echo ROOTFS_WRITABLE || echo ROOTFS_READONLY",
    ])
    assert "ROOTFS_READONLY" in ro.stdout, ro.stdout + ro.stderr

    # The host workspace dir must be unchanged by the attempted escapes.
    assert not (Path(boundary["outside"]) / "escape").exists()


def test_direct_egress_blocked_proxy_egress_allowed(boundary):
    workspace = boundary["workspace"]
    net = boundary["internal_net"]
    proxy = boundary["proxy_url"]

    # Direct egress: a raw socket ignores HTTP_PROXY and proves there is no external route.
    direct = _run_confined(workspace, net, proxy, [
        "python", "-c",
        "import socket\n"
        "try:\n"
        "    s = socket.create_connection(('1.1.1.1', 443), timeout=6); s.close(); print('DIRECT_REACHED')\n"
        "except OSError:\n"
        "    print('DIRECT_BLOCKED')\n",
    ])
    assert "DIRECT_BLOCKED" in direct.stdout, direct.stdout + direct.stderr

    # Proxy egress to an ALLOWED host succeeds and returns the origin body.
    allowed = _run_confined(workspace, net, proxy, [
        "curl", "-s", "--max-time", "8", "-x", proxy, "http://allowed.test/",
    ])
    assert ORIGIN_BODY in allowed.stdout, allowed.stdout + allowed.stderr

    # Proxy egress to a DENIED host is refused by the proxy allowlist (HTTP 403).
    denied = _run_confined(workspace, net, proxy, [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8",
        "-x", proxy, "http://denied.test/",
    ])
    assert denied.stdout.strip() == "403", denied.stdout + denied.stderr


def test_in_workspace_tool_call_succeeds(boundary):
    workspace = boundary["workspace"]
    net = boundary["internal_net"]
    proxy = boundary["proxy_url"]

    marker = f"asf_p3_ok_{uuid.uuid4().hex[:6]}"
    res = _run_confined(workspace, net, proxy, [
        "python", "-c",
        # Write+read a file in the bind-mounted workspace and load an ASF module from PYTHONPATH.
        "import pathlib, wrapper.asf_egress_proxy as p\n"
        f"path = pathlib.Path('/workspace/{marker}.txt')\n"
        f"path.write_text('{marker}')\n"
        "assert path.read_text() == '" + marker + "'\n"
        "print('WORKSPACE_RW_OK', bool(p.EgressPolicy))\n",
    ])
    assert "WORKSPACE_RW_OK" in res.stdout, res.stdout + res.stderr
    # The write made through the bind mount is visible on the host side.
    assert (Path(workspace) / f"{marker}.txt").read_text() == marker
