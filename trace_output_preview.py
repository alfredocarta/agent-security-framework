from __future__ import annotations

import json
from typing import Any


def _json_default(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return repr(value)


def pretty_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, default=_json_default)


def truncate_preview_text(text: str, max_bytes: int) -> str:
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text
    clipped = raw[:max_bytes].decode("utf-8", errors="ignore")
    return f"{clipped}…[truncated {len(raw) - max_bytes} bytes]"


def _looks_like_json_string(value: str) -> bool:
    stripped = value.strip()
    return bool(stripped) and stripped[0] in {"{", "[", '"'}


def unwrap_json_string(value: Any, max_depth: int = 3) -> Any:
    current = value
    for _ in range(max_depth):
        if not isinstance(current, str) or not _looks_like_json_string(current):
            break
        try:
            current = json.loads(current)
        except (TypeError, ValueError, json.JSONDecodeError):
            break
        if not isinstance(current, str):
            break
    return current


def output_preview_text(value: Any, max_bytes: int) -> str:
    unwrapped = unwrap_json_string(value)
    exit_code: Any = None
    has_exit_code = False

    if isinstance(unwrapped, dict):
        has_exit_code = "exit_code" in unwrapped
        exit_code = unwrapped.get("exit_code")
        file_value = unwrapped.get("file")
        if unwrapped.get("output") is not None:
            text = str(unwrapped.get("output"))
        elif "stdout" in unwrapped or "stderr" in unwrapped:
            stdout = unwrapped.get("stdout")
            stderr = unwrapped.get("stderr")
            text = "" if stdout is None else str(stdout)
            if stderr is not None and str(stderr) != "":
                text = f"{text}\nstderr: {stderr}"
        elif isinstance(unwrapped.get("content"), str):
            text = unwrapped["content"]
        elif isinstance(file_value, dict) and isinstance(file_value.get("content"), str):
            text = file_value["content"]
        else:
            text = pretty_json(unwrapped)
    elif isinstance(unwrapped, str):
        text = unwrapped
    else:
        text = pretty_json(unwrapped)

    if has_exit_code:
        try:
            is_non_zero = int(exit_code) != 0
        except (TypeError, ValueError):
            is_non_zero = exit_code not in (None, "", 0)
        if is_non_zero:
            text = f"{text}\nexit_code: {exit_code}"

    return truncate_preview_text(text, max_bytes)
