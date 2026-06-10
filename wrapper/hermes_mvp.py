from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from wrapper.asf_egress_proxy import EgressPolicy, parse_csv, parse_host_map, serve

ASF_ROOT = Path(__file__).resolve().parents[1]
REPO_PLUGIN = ASF_ROOT / "integrations" / "hermes" / "asf_tracker_plugin.py"
DEPLOYED_PLUGIN = Path.home() / ".hermes" / "plugins" / "asf-tracker" / "__init__.py"
DEFAULT_HERMES = Path.home() / ".local" / "bin" / "hermes"


def sync_plugin() -> None:
    DEPLOYED_PLUGIN.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO_PLUGIN, DEPLOYED_PLUGIN)


def build_env(
    mode: str,
    workdir: str,
    sandbox: bool,
    *,
    cmd_allow: str | None = None,
    path_allow: str | None = None,
    net_allow: str | None = None,
    proxy_port: int | None = None,
) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "ASF_ROOT": str(ASF_ROOT),
            "ASF_HERMES_ENABLED": "true",
            "ASF_HERMES_MODE": mode,
            "ASF_HERMES_SANDBOX": "true" if sandbox else "false",
            "ASF_HERMES_SANDBOX_WORKDIR": workdir,
            "ASF_STAGE3_BACKEND": env.get("ASF_STAGE3_BACKEND", "onnx"),
        }
    )
    if cmd_allow is not None:
        env["ASF_HERMES_CMD_ALLOW"] = cmd_allow
    if path_allow is not None:
        env["ASF_HERMES_PATH_ALLOW"] = path_allow
    if net_allow is not None:
        env["ASF_HERMES_NET_ALLOW"] = net_allow
    if proxy_port is not None:
        env["ASF_EGRESS_PROXY_PORT"] = str(proxy_port)
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Launch Hermes with the ASF plugin in explicit monitor or enforce mode."
    )
    parser.add_argument(
        "--mode",
        choices=("enforce", "monitor"),
        default=os.environ.get("ASF_HERMES_MODE", "enforce"),
        help="Use monitor as the anti-lockout kill-switch.",
    )
    parser.add_argument(
        "--workdir",
        default=os.environ.get(
            "ASF_HERMES_SANDBOX_WORKDIR",
            str(Path(tempfile.gettempdir()) / "asf-hermes-sandbox"),
        ),
        help="Writable sandbox root for terminal and execute_code tool subprocesses.",
    )
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Disable per-tool sandboxing. ASF pre-tool enforcement remains active.",
    )
    parser.add_argument(
        "--no-sync-plugin",
        action="store_true",
        help="Do not copy the vendored plugin to ~/.hermes/plugins/asf-tracker before launch.",
    )
    parser.add_argument(
        "--cmd-allow",
        default=os.environ.get("ASF_HERMES_CMD_ALLOW"),
        help="Comma separated executable allowlist enforced by the ASF Hermes plugin.",
    )
    parser.add_argument(
        "--path-allow",
        default=os.environ.get("ASF_HERMES_PATH_ALLOW"),
        help="Comma separated readable path allowlist. Writes remain confined to workdir.",
    )
    parser.add_argument(
        "--net-allow",
        default=os.environ.get("ASF_HERMES_NET_ALLOW"),
        help="Comma separated domain allowlist enforced by ASF intent checks and the local egress proxy.",
    )
    parser.add_argument(
        "--egress-proxy-port",
        type=int,
        default=int(os.environ.get("ASF_EGRESS_PROXY_PORT", "0")),
        help="Local ASF egress proxy port. Use 0 to choose a free port.",
    )
    parser.add_argument(
        "--egress-host-map",
        default=os.environ.get("ASF_EGRESS_HOST_MAP", ""),
        help="Test/dev mapping domain=ip[:port] used by the ASF egress proxy.",
    )
    parser.add_argument("hermes_args", nargs=argparse.REMAINDER, help="Arguments passed to hermes.")
    args = parser.parse_args(argv)

    workdir = str(Path(args.workdir).expanduser().resolve())
    Path(workdir).mkdir(parents=True, exist_ok=True)

    if not args.no_sync_plugin:
        sync_plugin()

    hermes = os.environ.get("HERMES_BIN", str(DEFAULT_HERMES))
    hermes_args = args.hermes_args
    if hermes_args and hermes_args[0] == "--":
        hermes_args = hermes_args[1:]
    if not hermes_args:
        hermes_args = ["chat"]

    proxy_server = None
    proxy_port = None
    if not args.no_sandbox and args.net_allow:
        policy = EgressPolicy(parse_csv(args.net_allow), parse_host_map(args.egress_host_map))
        proxy_server = serve("127.0.0.1", args.egress_proxy_port, policy)
        proxy_port = int(proxy_server.server_address[1])

    env = build_env(
        args.mode,
        workdir,
        sandbox=not args.no_sandbox,
        cmd_allow=args.cmd_allow,
        path_allow=args.path_allow,
        net_allow=args.net_allow,
        proxy_port=proxy_port,
    )
    print(
        f"[ASF Hermes wrapper] mode={args.mode} sandbox={not args.no_sandbox} workdir={workdir}",
        file=sys.stderr,
    )
    if args.mode == "monitor":
        print("[ASF Hermes wrapper] monitor mode kill-switch active: ASF logs but does not veto", file=sys.stderr)
    else:
        print(
            "[ASF Hermes wrapper] HITL pauses pre-tool calls until dashboard approval, rejection, or timeout",
            file=sys.stderr,
        )
    if args.net_allow:
        if proxy_port is not None:
            print(
                f"[ASF Hermes wrapper] egress proxy active on 127.0.0.1:{proxy_port}; "
                "tool subprocess network is OS-limited to the proxy and domains are proxy-enforced",
                file=sys.stderr,
            )
        else:
            print(
                "[ASF Hermes wrapper] net allowlist is ASF intent-level only because sandbox/proxy is disabled",
                file=sys.stderr,
            )
    if not args.no_sandbox:
        print(
            "[ASF Hermes wrapper] sandbox scope: terminal/execute_code subprocesses only; "
            "writes confined to workdir, network limited to proxy when configured, reads are not confined; "
            "Hermes runtime and in-process tools are not sandboxed",
            file=sys.stderr,
        )

    try:
        return subprocess.call([hermes, *hermes_args], env=env)
    finally:
        if proxy_server is not None:
            proxy_server.shutdown()
            proxy_server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
