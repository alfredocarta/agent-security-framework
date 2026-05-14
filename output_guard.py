from __future__ import annotations

import re
from typing import Tuple

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


def check_output(result: str, canary: str) -> Tuple[bool, str]:
    """
    Inspect tool output for security issues.
    Returns (is_dangerous, reason).
    """
    if not result:
        return False, ""

    # Check canary trap first
    if canary and canary in result:
        return True, f"Canary trap triggered: {canary}"

    # Check secret patterns
    for pattern, name in SECRET_PATTERNS:
        if re.search(pattern, result):
            return True, f"Secret detected: {name}"

    # Check for bulk data exfiltration (many rows)
    if isinstance(result, str) and result.count("{") > 10:
        return True, "Potential bulk data exfiltration (>10 records)"

    return False, ""
