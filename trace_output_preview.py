from __future__ import annotations

import json
from typing import Any
import canonical_log
from secret_redaction import redact_text


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


# Priority keys whose string value is the human-facing output, tried in order.
_CONTENT_KEYS = ("output", "stdout", "content", "text", "result", "message", "body")

# Structural/metadata keys that are never the output. Compared lowercased. stderr and exit_code are
# excluded here on purpose: they are appended by output_preview_text after the primary text.
_NOISE_KEYS = frozenset({
    "originalfile", "filepath", "file_path", "path", "type", "numlines", "totallines", "startline",
    "offset", "limit", "interrupted", "isimage", "nooutputexpected", "sandboxed", "sandbox_warning",
    "mode", "gitoperation", "durationms", "duration_ms", "returncode", "exit_code", "stderr",
})


def _extract_envelope_text(value: Any, depth: int = 0) -> str:
    # Generic, tool-agnostic extraction of the readable text from an arbitrary result envelope.
    value = unwrap_json_string(value)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(value) if value and all(isinstance(i, str) for i in value) else pretty_json(value)
    if not isinstance(value, dict):
        return pretty_json(value)

    for key in _CONTENT_KEYS:
        if isinstance(value.get(key), str):
            return value[key]

    if depth < 2:
        for nested in value.values():
            if isinstance(nested, dict):
                inner = _extract_envelope_text(nested, depth + 1)
                if inner and not inner.lstrip().startswith(("{", "[")):
                    return inner

    # A primary list of strings (search_files, glob, grep, ...) renders as newline-joined lines.
    for k, v in value.items():
        if k.lower() not in _NOISE_KEYS and isinstance(v, list) and v and all(isinstance(i, str) for i in v):
            return "\n".join(v)

    labeled = [
        (k, v) for k, v in value.items()
        if isinstance(v, str) and v.strip() and k.lower() not in _NOISE_KEYS
    ]
    if len(labeled) == 1:
        return labeled[0][1]
    if labeled:
        return "\n\n".join(f"{k}:\n{v}" for k, v in labeled)

    denoised = {k: v for k, v in value.items() if k.lower() not in _NOISE_KEYS}
    return pretty_json(denoised if denoised else value)


def output_preview_text(value: Any, max_bytes: int) -> str:
    unwrapped = unwrap_json_string(value)
    text = _extract_envelope_text(unwrapped)

    if isinstance(unwrapped, dict):
        stderr = unwrapped.get("stderr")
        if stderr is not None and str(stderr) != "":
            text = f"{text}\nstderr: {stderr}"
        if "exit_code" in unwrapped:
            exit_code = unwrapped.get("exit_code")
            try:
                is_non_zero = int(exit_code) != 0
            except (TypeError, ValueError):
                is_non_zero = exit_code not in (None, "", 0)
            if is_non_zero:
                text = f"{text}\nexit_code: {exit_code}"

    preview = truncate_preview_text(redact_text(text), max_bytes)
    # Log the preview input as structured JSON so input_id is based on the same
    # sorted-key/compact canonical serialization as Rust, not Python dict repr.
    canonical_log.log("trace_output_preview", "py", unwrapped, {"preview": preview})
    return preview
