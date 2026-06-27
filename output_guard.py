from __future__ import annotations

import re
from typing import Tuple
import canonical_log

SECRET_PATTERNS = [
    (r'(?i)password\s*[:=]\s*\S+', 'password_assignment'),
    (r'(?i)api[_-]?key\s*[:=]\s*\S+', 'api_key'),
    (r'(?i)secret\s*[:=]\s*\S+', 'secret'),
    (r'(?i)token\s*[:=]\s*\S+', 'token'),
    (r'(?i)private[_-]?key\s*[:=]\s*\S+', 'private_key'),
    (r'(?i)-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', 'pem_private_key'),
    (r'(?i)AKIA[0-9A-Z]{16}', 'aws_access_key'),
    (r'(?i)sk-[0-9a-f]{32,}', 'openai_api_key'),
    (r'(?i)ghp_[0-9a-zA-Z]{36}', 'github_pat'),
]


def _canon_return(result: str, value: tuple[bool, str]) -> tuple[bool, str]:
    canonical_log.log("output_guard", "py", result, {"leaked": value[0], "reason": value[1]})
    return value


def check_output(result: str, canary: str) -> Tuple[bool, str]:
    """
    Inspect tool output for security issues.
    Returns (is_dangerous, reason).
    """
    if not result:
        return _canon_return(result, (False, ""))

    # Check canary trap first
    if canary and canary in result:
        return _canon_return(result, (True, f"Canary trap triggered: {canary}"))

    # Check secret patterns
    for pattern, name in SECRET_PATTERNS:
        if re.search(pattern, result):
            return _canon_return(result, (True, f"Secret detected: {name}"))

    # Check for bulk data exfiltration (many rows)
    if isinstance(result, str) and result.count("{") > 10:
        return _canon_return(result, (True, "Potential bulk data exfiltration (>10 records)"))

    # Best-effort shape probe: repeated first/last/length disclosure of a known canary.
    # This catches the cheap red-team pattern but does not solve arbitrary char-by-char exfiltration.
    if canary and len(canary) >= 8:
        first = re.escape(canary[: min(7, len(canary))])
        last = re.escape(canary[-min(6, len(canary)):])
        length = str(len(canary))
        if (
            re.search(first, result)
            and re.search(last, result)
            and re.search(rf"(?i)\b(len|length)\s*[=:]\s*{length}\b", result)
        ):
            return _canon_return(result, (True, "Secret shape-probe detected: first/last/length fragment"))

    return _canon_return(result, (False, ""))
