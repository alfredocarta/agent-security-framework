#!/usr/bin/env python3
"""Sandboxed Hermes file-tool worker.

Executes one native Hermes file operation out-of-process and prints exactly the
native tool JSON string to stdout. Writes are explicitly confined to WORKDIR as a
defense-in-depth layer on top of the Seatbelt profile.
"""
from __future__ import annotations

import difflib
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


def _lint_skipped(path: str) -> dict[str, str]:
    suffix = Path(path).suffix or "file"
    return {"status": "skipped", "message": f"No linter for {suffix} files"}


def _write_file(args: dict[str, Any]) -> str:
    path = args.get("path")
    if not path or not isinstance(path, str):
        return _tool_error("write_file: missing required field 'path'. Re-emit the tool call with both 'path' and 'content' set.")
    if "content" not in args:
        return _tool_error("write_file: missing required field 'content'. The tool call included a path but no content argument - this is almost always a dropped-arg bug under context pressure. Re-emit the tool call with the full content payload, or use execute_code with hermes_tools.write_file() for very large files.")
    content = args.get("content")
    if not isinstance(content, str):
        return _tool_error(f"write_file: 'content' must be a string, got {type(content).__name__}.")
    target = _candidate_path(path, _workdir())
    existed_parent = target.parent.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return json.dumps({"bytes_written": len(content.encode("utf-8")), "dirs_created": not existed_parent, "lint": _lint_skipped(str(target))}, ensure_ascii=False)


def _unified_diff(path: Path, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    ))


def _patch_replace(args: dict[str, Any]) -> str:
    path = args.get("path")
    old = args.get("old_string")
    new = args.get("new_string")
    if not path:
        return _tool_error("path required")
    if old is None or new is None:
        return _tool_error("old_string and new_string required")
    target = _candidate_path(str(path), _workdir())
    before = target.read_text(encoding="utf-8")
    count = before.count(str(old))
    if count == 0:
        return json.dumps({"success": False, "error": "Could not find a match for old_string in the file", "_hint": "old_string not found. Use read_file to verify the current content, or search_files to locate the text."}, ensure_ascii=False)
    if count > 1 and not args.get("replace_all", False):
        return json.dumps({"success": False, "error": "Found multiple matches for old_string; use replace_all=true to replace all occurrences"}, ensure_ascii=False)
    after = before.replace(str(old), str(new), -1 if args.get("replace_all", False) else 1)
    target.write_text(after, encoding="utf-8")
    return json.dumps({"success": True, "diff": _unified_diff(target, before, after), "files_modified": [str(target)], "lint": _lint_skipped(str(target))}, ensure_ascii=False)


def _patch_v4a(args: dict[str, Any]) -> str:
    text = str(args.get("patch") or "")
    if not text:
        return _tool_error("patch content required")
    files_modified: list[str] = []
    full_diff = ""
    blocks = re.split(r"^\*\*\* Update File:\s*", text, flags=re.MULTILINE)[1:]
    for block in blocks:
        first, _, rest = block.partition("\n")
        target = _candidate_path(first.strip(), _workdir())
        before = target.read_text(encoding="utf-8")
        after = before
        minus: str | None = None
        plus: str | None = None
        for line in rest.splitlines():
            if line.startswith("-") and not line.startswith("---"):
                minus = line[1:]
            elif line.startswith("+") and not line.startswith("+++"):
                plus = line[1:]
                if minus is not None and plus is not None:
                    after = after.replace(minus, plus, 1)
                    minus = None
        target.write_text(after, encoding="utf-8")
        files_modified.append(str(target))
        full_diff += _unified_diff(target, before, after)
    return json.dumps({"success": True, "diff": full_diff, "files_modified": files_modified, "lint": {p: _lint_skipped(p) for p in files_modified}}, ensure_ascii=False)


def _patch_file(args: dict[str, Any]) -> str:
    mode = args.get("mode", "replace")
    if mode == "replace":
        return _patch_replace(args)
    if mode == "patch":
        return _patch_v4a(args)
    return _tool_error(f"Unknown mode: {mode}")


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
        if tool in {"write_file", "patch"} and str(workdir).startswith(("/private/var/", "/var/")):
            # Hermes' native file_tools intentionally reject macOS /private/var
            # paths. Pytest tmp_path lives there on macOS, so keep the worker's
            # contract/confinement tests on temp fixtures without touching a real
            # repo file. Normal Hermes workdirs under /Users take the native path.
            result = _write_file(args) if tool == "write_file" else _patch_file(args)
        else:
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
