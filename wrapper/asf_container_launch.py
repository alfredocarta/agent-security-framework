"""ASF Phase 3 launcher: run the WHOLE Hermes agent inside a host-confined container.

This is an OPT-IN, enforced-mode launcher that is deliberately separate from the
existing wrapper/hermes_mvp.py path (which only sandboxes terminal/execute_code
subprocesses via macOS Seatbelt). Nothing here changes that path; importing or not
running this module has no effect on the cooperative wrapper.

What the host enforces here (see docs/sandbox_phase3_design.md):
  - Filesystem: the project workspace is the ONLY bind mount (rw at /workspace).
    No home, no SSH/cloud creds, no Docker socket. Root fs is read-only; /tmp is tmpfs.
  - Network: the container runs on an `--internal` Docker network with NO external
    route. The ONLY way out is the ASF egress proxy (wrapper/asf_egress_proxy.py),
    run as a sidecar bridging the internal network and an external network. Direct
    egress is denied by the Docker/VM kernel, not by cooperative code.
  - Privilege: --cap-drop ALL, --security-opt no-new-privileges, seccomp profile,
    non-root user, and CPU/memory/PID limits.

The Hermes runtime binary itself is NOT baked into the image; supply it by mounting
a prebuilt runtime read-only at ASF_HERMES_AGENT_ROOT, or extend Dockerfile.phase3.
The boundary this launcher applies is independent of how Hermes is provided.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from wrapper.env_scrub import scrub_env

ASF_ROOT = Path(__file__).resolve().parents[1]
SECCOMP_PROFILE = ASF_ROOT / "wrapper" / "asf_phase3_seccomp.json"

DEFAULT_IMAGE = "asf-hermes:phase3"
DEFAULT_PROXY_PORT = 8888

# Resource limits (host-enforced; a fork bomb or memory hog inside cannot exhaust the host).
DEFAULT_PIDS_LIMIT = 256
DEFAULT_MEMORY = "1g"
DEFAULT_CPUS = "2"


def _run(cmd: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def docker_available() -> bool:
    """True only if a docker CLI exists AND the daemon answers. Mirrors test_sandbox.py intent."""
    try:
        _run(["docker", "info"], check=True, capture=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def image_exists(image: str = DEFAULT_IMAGE) -> bool:
    result = _run(["docker", "image", "inspect", image], check=False, capture=True)
    return result.returncode == 0


def build_image(image: str = DEFAULT_IMAGE, *, dockerfile: str = "Dockerfile.phase3") -> None:
    _run(["docker", "build", "-t", image, "-f", str(ASF_ROOT / dockerfile), str(ASF_ROOT)])


def ensure_network(name: str, *, internal: bool = False) -> None:
    if _run(["docker", "network", "inspect", name], check=False, capture=True).returncode == 0:
        return
    cmd = ["docker", "network", "create"]
    if internal:
        cmd.append("--internal")
    cmd.append(name)
    _run(cmd, capture=True)


def remove_network(name: str) -> None:
    _run(["docker", "network", "rm", name], check=False, capture=True)


def start_proxy_sidecar(
    *,
    image: str,
    external_net: str,
    internal_net: str,
    name: str,
    allowlist: str,
    host_map: str = "",
    port: int = DEFAULT_PROXY_PORT,
) -> str:
    """Start the ASF egress proxy as a sidecar bridging external<->internal nets.

    Returns the proxy URL reachable from the confined container (http://<name>:<port>).
    The sidecar runs the SAME wrapper/asf_egress_proxy.py used by the host wrapper, so
    the allowlist/host-map semantics are identical. It is the only egress channel.
    """
    _run(
        [
            "docker", "run", "-d", "--rm", "--name", name,
            "--network", external_net,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "-e", f"ASF_HERMES_NET_ALLOW={allowlist}",
            "-e", f"ASF_EGRESS_HOST_MAP={host_map}",
            image,
            "python", "-m", "wrapper.asf_egress_proxy",
            "--host", "0.0.0.0", "--port", str(port),
        ],
        capture=True,
    )
    # A container is created on a single network; attach the second one explicitly.
    _run(["docker", "network", "connect", internal_net, name], capture=True)
    return f"http://{name}:{port}"


def hardened_run_args(
    *,
    workspace: str,
    image: str,
    network: str,
    proxy_url: str | None,
    name: str | None = None,
    command: list[str] | None = None,
    detach: bool = False,
    remove: bool = True,
    extra_env: dict[str, str] | None = None,
    allowlist: str = "",
) -> list[str]:
    """Build the full `docker run` argv that applies the host-enforced boundary.

    This is the single source of truth for the confinement flags; the smoke test
    imports it so the test exercises exactly what production would run.
    """
    workspace_path = str(Path(workspace).expanduser().resolve())
    args: list[str] = ["docker", "run"]
    if remove:
        args.append("--rm")
    if detach:
        args.append("-d")
    if name:
        args += ["--name", name]

    # Network: an internal (no external route) network when egress must be proxy-only.
    args += ["--network", network]

    # Filesystem: workspace is the ONLY bind mount; everything else read-only or tmpfs.
    args += ["--read-only"]
    args += ["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"]
    args += ["--tmpfs", "/var/tmp:rw,noexec,nosuid,size=16m"]
    args += ["--tmpfs", "/home/asf/.cache:rw,noexec,nosuid,size=64m"]
    args += ["-v", f"{workspace_path}:/workspace:rw"]
    # Explicitly DO NOT mount: $HOME, ~/.ssh, ~/.aws, cloud creds, or /var/run/docker.sock.

    # Privilege reduction.
    args += ["--cap-drop", "ALL"]
    args += ["--security-opt", "no-new-privileges:true"]
    if SECCOMP_PROFILE.exists():
        args += ["--security-opt", f"seccomp={SECCOMP_PROFILE}"]
    args += ["--user", "1000:1000"]

    # Resource limits.
    args += ["--pids-limit", str(DEFAULT_PIDS_LIMIT)]
    args += ["--memory", DEFAULT_MEMORY, "--memory-swap", DEFAULT_MEMORY]
    args += ["--cpus", DEFAULT_CPUS]

    # Enforce-mode env for the ASF plugin running inside the container.
    env: dict[str, str] = {
        "ASF_ROOT": "/opt/asf",
        "ASF_CONTAINER_MODE": "true",
        "ASF_HERMES_ENABLED": "true",
        "ASF_HERMES_MODE": "enforce",
        "ASF_HERMES_NET_ALLOW": allowlist,
    }
    if proxy_url:
        # Force application egress through the proxy; the internal network blocks any
        # path that ignores these (defence in depth, not the sole control).
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env[key] = proxy_url
        env["NO_PROXY"] = "localhost,127.0.0.1"
    if extra_env:
        env.update(extra_env)
    scrub_env(env)
    for key, value in env.items():
        args += ["-e", f"{key}={value}"]

    args.append(image)
    if command:
        args += command
    return args


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Hermes inside a host-enforced ASF container (opt-in, enforce mode)."
    )
    parser.add_argument("--workspace", default=str(Path.cwd()),
                        help="Project directory bind-mounted (rw) at /workspace. The ONLY host mount.")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--build", action="store_true", help="Build the image before launch.")
    parser.add_argument("--net-allow", default="",
                        help="Comma-separated egress domain allowlist. Empty means deny all egress.")
    parser.add_argument("--egress-host-map", default="",
                        help="Optional domain=ip[:port] map for the egress proxy (test/dev).")
    parser.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT)
    parser.add_argument("--prefix", default="asf-phase3",
                        help="Name prefix for the created containers and networks.")
    parser.add_argument("hermes_args", nargs=argparse.REMAINDER,
                        help="Command to run inside the container (default: ASF enforce self-check).")
    args = parser.parse_args(argv)

    if not docker_available():
        print("[ASF phase3] Docker is not available; cannot launch the host-enforced boundary.",
              file=sys.stderr)
        return 2

    if args.build or not image_exists(args.image):
        print(f"[ASF phase3] Building image {args.image} ...", file=sys.stderr)
        build_image(args.image)

    internal_net = f"{args.prefix}-int"
    external_net = f"{args.prefix}-ext"
    proxy_name = f"{args.prefix}-proxy"

    command = args.hermes_args
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        command = [
            "python", "-c",
            "import os; print('[ASF phase3] Hermes enforce-mode container active');"
            " print(' mode =', os.environ.get('ASF_HERMES_MODE'));"
            " print(' egress proxy =', os.environ.get('HTTP_PROXY'));"
            " print(' net allow =', os.environ.get('ASF_HERMES_NET_ALLOW') or '(deny all)');"
            " print(' NOTE: mount a Hermes runtime at ASF_HERMES_AGENT_ROOT to run `hermes chat` here.')",
        ]

    ensure_network(external_net, internal=False)
    ensure_network(internal_net, internal=True)
    proxy_url = start_proxy_sidecar(
        image=args.image,
        external_net=external_net,
        internal_net=internal_net,
        name=proxy_name,
        allowlist=args.net_allow,
        host_map=args.egress_host_map,
        port=args.proxy_port,
    )
    print(f"[ASF phase3] egress proxy sidecar at {proxy_url}; direct egress is kernel-denied",
          file=sys.stderr)
    print(f"[ASF phase3] workspace {args.workspace} mounted rw at /workspace; root fs read-only",
          file=sys.stderr)

    run_args = hardened_run_args(
        workspace=args.workspace,
        image=args.image,
        network=internal_net,
        proxy_url=proxy_url,
        command=command,
        allowlist=args.net_allow,
    )
    try:
        return subprocess.call(run_args)
    finally:
        _run(["docker", "rm", "-f", proxy_name], check=False, capture=True)
        remove_network(internal_net)
        remove_network(external_net)


if __name__ == "__main__":
    raise SystemExit(main())
