from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, TypedDict

from wrapper import asf_core


def _resolve_asf_root() -> Path:
    env_root = os.environ.get("ASF_ROOT")
    if env_root:
        return Path(env_root)
    return Path(__file__).resolve().parents[1]


DEFAULT_ASF_ROOT = _resolve_asf_root()


def _env_bool_any(names: tuple[str, ...], default: bool) -> bool:
    for name in names:
        if name in os.environ:
            return asf_core.env_bool(name, default)
    return default


def _env_value_any(names: tuple[str, ...], default: str) -> str:
    for name in names:
        value = os.environ.get(name)
        if value is not None:
            return value
    return default


def enabled() -> bool:
    return _env_bool_any(("ASF_LANGGRAPH_ENABLED", "ASF_HERMES_ENABLED"), True)


def mode() -> str:
    return _env_value_any(("ASF_LANGGRAPH_MODE", "ASF_HERMES_MODE"), "monitor").strip().lower()


def agent_id() -> str:
    return _env_value_any(("ASF_AGENT_ID", "ASF_LANGGRAPH_AGENT_ID"), asf_core.DEFAULT_AGENT_ID)


def register_langgraph_agent(resolved_agent_id: str | None = None) -> None:
    try:
        import registry

        resolved_agent_id = resolved_agent_id or agent_id()
        permissions = sorted(set(asf_core.DEFAULT_TOOL_MAP.values()) | {"shell", "code_execution", "communication"})
        if asf_core.env_bool("ASF_LANGGRAPH_REGISTRY_RESET", False):
            registry.add_or_update_agent(
                resolved_agent_id,
                risk_level=os.environ.get("ASF_LANGGRAPH_RISK_LEVEL", "high"),
                permissions=permissions,
            )
            if hasattr(registry, "reinstate_agent"):
                registry.reinstate_agent(resolved_agent_id)
            return
        if not (registry.agent_exists(resolved_agent_id) if hasattr(registry, "agent_exists") else False):
            registry.add_or_update_agent(
                resolved_agent_id,
                risk_level=os.environ.get("ASF_LANGGRAPH_RISK_LEVEL", "high"),
                permissions=permissions,
            )
    except Exception:
        if asf_core.env_bool("ASF_LANGGRAPH_FAIL_CLOSED", asf_core.env_bool("ASF_HERMES_FAIL_CLOSED", False)):
            raise


def run_asf_check(agent: str, asf_tool: str, security_text: str, session_id: str | None = None) -> tuple[str, str]:
    register_langgraph_agent(agent)
    return asf_core.run_asf_check(agent, asf_tool, security_text, session_id=session_id)


def build_security_text(tool_name: str, args: dict[str, Any] | None) -> str:
    args = args or {}
    asf_tool = asf_core.normalize_tool_name(tool_name)
    parts = ["source=langgraph", f"tool={tool_name}", f"asf_tool={asf_tool}"]
    if tool_name in {"terminal", "shell"}:
        parts.append(f"command={asf_core.safe_preview(args.get('command', ''))}")
    elif tool_name in {"execute_code", "python"}:
        parts.append(f"code={asf_core.safe_preview(args.get('code', ''))}")
    else:
        parts.append(f"args={asf_core.safe_preview(args)}")
    return "\n".join(parts)


class ToolBlocked(RuntimeError):
    pass


class AsfLangGraphToolWrapper:
    def __init__(
        self,
        tools: dict[str, Callable[[dict[str, Any]], Any]] | None = None,
        *,
        agent: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        check_fn: Callable[[str, str, str, str | None], tuple[str, str]] | None = None,
    ):
        self.tools = tools or default_tools()
        self.agent = agent or agent_id()
        self.session_id = session_id
        self.task_id = task_id
        self.check_fn = check_fn

    def call_tool(self, tool_name: str, args: dict[str, Any] | None = None, *, tool_call_id: str | None = None) -> Any:
        args = args if isinstance(args, dict) else {}
        if not enabled():
            return self._execute(tool_name, args)

        if mode() == "enforce":
            reason = asf_core.allowlist_block_reason(tool_name, args)
            if reason is not None:
                self._persist_policy_block(tool_name, reason, args, tool_call_id)
                raise ToolBlocked(f"[ASF BLOCKED] {reason}")

        asf_tool = asf_core.normalize_tool_name(tool_name)
        security_text = build_security_text(tool_name, args)
        decision = asf_core.asf_decision(
            agent_id=self.agent,
            asf_tool=asf_tool,
            security_text=security_text,
            action_id=tool_call_id,
            session_id=self.session_id,
            fail_closed_env="ASF_LANGGRAPH_FAIL_CLOSED",
            check_fn=self.check_fn or (lambda agent, tool, text, sid: run_asf_check(agent, tool, text, session_id=sid)),
            register_fn=lambda: register_langgraph_agent(self.agent),
        )
        asf_core.start_call_trace(
            agent_id=self.agent,
            source_tool_name=tool_name,
            asf_tool_name=asf_tool,
            args=args,
            verdict=decision.verdict,
            outcome=asf_core.outcome_from_verdict(decision.verdict),
            reason=decision.reason,
            latency_ms=decision.latency_ms,
            audit_hash=decision.audit_hash,
            session_id=self.session_id,
            task_id=self.task_id,
            tool_call_id=tool_call_id,
            agent_type="langgraph-agent",
        )

        if mode() == "enforce":
            if decision.verdict.upper() == "DENY":
                raise ToolBlocked(f"[ASF BLOCKED] {decision.reason}")
            if decision.verdict.upper() == "HITL":
                if not decision.audit_hash:
                    raise ToolBlocked(f"[ASF HITL] Human approval required: No HITL event hash available: {decision.reason}")
                approved, hitl_reason = asf_core.wait_for_hitl_decision(decision.audit_hash, decision.reason)
                if not approved:
                    raise ToolBlocked(f"[ASF HITL] Human approval required: {hitl_reason}")

        start = time.monotonic()
        side_effect_occurred = None
        result: Any = None
        try:
            result = self._execute(tool_name, args)
            side_effect_occurred = True
            return result
        except Exception as exc:
            side_effect_occurred = False
            result = {"error": str(exc), "type": type(exc).__name__}
            raise
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            asf_core.finish_call_trace(
                source_tool_name=tool_name,
                args=args,
                result=result,
                session_id=self.session_id,
                task_id=self.task_id,
                tool_call_id=tool_call_id,
                duration_ms=duration_ms,
                side_effect_verified=True,
                side_effect_occurred=side_effect_occurred,
            )

    def _persist_policy_block(self, tool_name: str, reason: str, args: dict[str, Any], tool_call_id: str | None) -> None:
        register_langgraph_agent(self.agent)
        try:
            from audit import AUDITOR

            AUDITOR.log_event(self.agent, asf_core.normalize_tool_name(tool_name), "BLOCKED", reason, session_id=self.session_id)
            audit_hash = AUDITOR.last_hash_for(self.agent)
        except Exception:
            audit_hash = None
        asf_core.start_call_trace(
            agent_id=self.agent,
            source_tool_name=tool_name,
            asf_tool_name=asf_core.normalize_tool_name(tool_name),
            args=args,
            verdict="DENY",
            outcome="BLOCKED",
            reason=reason,
            latency_ms=0,
            audit_hash=audit_hash,
            session_id=self.session_id,
            task_id=self.task_id,
            tool_call_id=tool_call_id,
            agent_type="langgraph-agent",
        )

    def _execute(self, tool_name: str, args: dict[str, Any]) -> Any:
        if tool_name in {"terminal", "shell"}:
            if asf_core.sandbox_enabled():
                return json.loads(asf_core.sandbox_terminal(args, asf_root=DEFAULT_ASF_ROOT))
            completed = subprocess.run(
                ["/bin/sh", "-c", str(args.get("command", ""))],
                cwd=args.get("workdir") or None,
                text=True,
                capture_output=True,
                timeout=args.get("timeout") or 30,
                check=False,
            )
            return {"output": completed.stdout, "stderr": completed.stderr, "exit_code": completed.returncode, "sandboxed": False}
        if tool_name in {"execute_code", "python"}:
            if asf_core.sandbox_enabled():
                return json.loads(asf_core.sandbox_execute_code(args, asf_root=DEFAULT_ASF_ROOT))
            completed = subprocess.run(
                [sys.executable, "-c", str(args.get("code", ""))],
                cwd=args.get("workdir") or None,
                text=True,
                capture_output=True,
                timeout=args.get("timeout") or 30,
                check=False,
            )
            return {"output": completed.stdout, "stderr": completed.stderr, "exit_code": completed.returncode, "sandboxed": False}
        if tool_name not in self.tools:
            raise KeyError(f"Unknown LangGraph tool: {tool_name}")
        return self.tools[tool_name](args)


def default_tools() -> dict[str, Callable[[dict[str, Any]], Any]]:
    return {
        "echo": lambda args: f"echo:{args.get('text', '')}",
        "benign_lookup": lambda args: {"lookup": args.get("query", ""), "ok": True},
    }


class DemoState(TypedDict, total=False):
    agent_id: str
    tool_name: str
    args: dict[str, Any]
    session_id: str
    task_id: str
    tool_call_id: str
    result: Any
    error: str
    log: list[str]


def tool_node(state: DemoState) -> dict[str, Any]:
    wrapper = AsfLangGraphToolWrapper(
        agent=state.get("agent_id") or agent_id(),
        session_id=state.get("session_id"),
        task_id=state.get("task_id"),
    )
    try:
        result = wrapper.call_tool(
            state.get("tool_name", "echo"),
            state.get("args", {}),
            tool_call_id=state.get("tool_call_id"),
        )
        return {"result": result, "log": state.get("log", []) + ["tool executed"]}
    except ToolBlocked as exc:
        return {"error": str(exc), "log": state.get("log", []) + ["tool blocked"]}


def build_demo_graph():
    try:
        from langgraph.graph import END, StateGraph
    except Exception as exc:
        raise RuntimeError("langgraph is required for build_demo_graph") from exc

    graph = StateGraph(DemoState)
    graph.add_node("tool", tool_node)
    graph.set_entry_point("tool")
    graph.add_edge("tool", END)
    return graph.compile()
