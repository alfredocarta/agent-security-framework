#!/usr/bin/env python3
"""Sandboxed Hermes file-tool worker.

Executes one native Hermes file operation out-of-process and prints exactly the
native tool JSON string to stdout. Writes are explicitly confined to WORKDIR as a
defense-in-depth layer on top of the Seatbelt profile.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

FILE_TOOLS = {"read_file", "write_file", "patch", "search_files"}
WRITE_TOOLS = {"write_file", "patch"}


def _tool_error(message: str) -> str:
    return json.dumps({"error": message}, ensure_ascii=False)


def _load_request() -> dict[str, Any]:
    if len(sys.argv) > 1:
        return json.loads(sys.argv[1])
    raw = sys.stdin.read()
    return json.loads(raw or "{}")


def _workdir() -> Path:
    value = os.environ.get("ASF_HERMES_SANDBOX_WORKDIR") or os.environ.get("WORKDIR")
    if not value:
        value = os.getcwd()
    return Path(value).expanduser().resolve()


def _candidate_path(raw: str | None, workdir: Path) -> Path:
    if not raw:
        return workdir
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = workdir / p
    return p


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _reject_write_path(raw: str | None, workdir: Path) -> str | None:
    if not raw or not isinstance(raw, str):
        return "write target path is required"
    target = _candidate_path(raw, workdir)

    # Resolve the parent even when the target does not exist. This follows any
    # existing parent symlinks so symlink escapes are caught before the write.
    try:
        parent_resolved = target.parent.resolve(strict=True)
    except FileNotFoundError:
        try:
            parent_resolved = target.parent.resolve(strict=False)
        except OSError as exc:
            return f"write target cannot be resolved: {raw}: {exc}"
    except OSError as exc:
        return f"write target cannot be resolved: {raw}: {exc}"

    if not _is_within(parent_resolved, workdir):
        return f"write target is outside WORKDIR: {raw}"

    if target.exists() or target.is_symlink():
        try:
            target_resolved = target.resolve(strict=True)
        except OSError as exc:
            return f"write target cannot be resolved: {raw}: {exc}"
        if not _is_within(target_resolved, workdir):
            return f"write target is outside WORKDIR: {raw}"
        if target.is_symlink() and target_resolved != target.absolute():
            # Reject all symlink targets for writes. This is stricter than the
            # minimum out-of-WORKDIR check and prevents TOCTOU-style surprises.
            return f"write target is a symlink and is rejected: {raw}"
    return None


def _extract_patch_paths(patch_text: str) -> list[str]:
    paths: list[str] = []
    for match in re.finditer(r"^\*\*\*\s+(?:Update|Add|Delete)\s+File:\s*(.+)$", patch_text or "", re.MULTILINE):
        path = match.group(1).strip()
        if path:
            paths.append(path)
    return paths


def _check_write_confinement(tool: str, args: dict[str, Any], workdir: Path) -> str | None:
    if tool == "write_file":
        return _reject_write_path(args.get("path"), workdir)
    if tool == "patch":
        mode = args.get("mode", "replace")
        paths = [args.get("path")] if mode == "replace" else _extract_patch_paths(str(args.get("patch", "")))
        if not paths:
            return "patch write target path is required"
        for p in paths:
            err = _reject_write_path(p, workdir)
            if err:
                return err
    return None


def _import_native_registry() -> Any:
    hermes_root = os.environ.get("ASF_HERMES_AGENT_ROOT") or str(Path.home() / ".hermes" / "hermes-agent")
    if hermes_root not in sys.path:
        sys.path.insert(0, hermes_root)
    import tools.file_tools  # type: ignore[import-not-found]  # noqa: F401 - registers file handlers
    from tools.registry import registry  # type: ignore[import-not-found]
    return registry


def main() -> int:
    try:
        req = _load_request()
    except Exception as exc:
        print(_tool_error(f"invalid worker request: {exc}"))
        return 0

    tool = str(req.get("tool") or req.get("name") or "")
    raw_args = req.get("args")
    args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
    raw_kwargs = req.get("kwargs")
    kwargs: dict[str, Any] = raw_kwargs if isinstance(raw_kwargs, dict) else {}
    if tool not in FILE_TOOLS:
        print(_tool_error(f"unsupported file tool: {tool}"))
        return 0

    workdir = _workdir()
    if tool in WRITE_TOOLS:
        err = _check_write_confinement(tool, args, workdir)
        if err:
            print(_tool_error(err))
            return 0

    try:
        os.environ.setdefault("HERMES_WRITE_SAFE_ROOT", str(workdir))
        registry = _import_native_registry()
        result = registry.dispatch(tool, args, **kwargs)
        if isinstance(result, str):
            print(result)
        else:
            print(json.dumps(result, ensure_ascii=False))
    except Exception as exc:
        print(_tool_error(f"Tool execution failed: {type(exc).__name__}: {exc}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
