from __future__ import annotations

import os
import re
from typing import Any

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\s*[=:]\s*[^\s'\"]{8,}"),
    re.compile(r"(?i)\b(bearer)\s+[a-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\bsk-[a-z0-9._-]{8,}"),
    re.compile(r"(?i)\bghp_[a-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)

REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_CANARY = "[REDACTED_CANARY]"


def redact_text(text: str) -> str:
    redacted = str(text)
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED_SECRET, redacted)
    for env_name in ("ASF_HOOK_CANARY", "ASF_HERMES_CANARY"):
        canary = os.environ.get(env_name)
        if canary:
            redacted = redacted.replace(canary, REDACTED_CANARY)
    return redacted


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes):
        return redact_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v) for v in value)
    return value
