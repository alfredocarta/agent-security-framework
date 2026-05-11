from __future__ import annotations

import hashlib
import math
import re
import uuid
from typing import Callable

# ---------------------------------------------------------------------------
# L1.5 Hardening - composable security wrappers
# ---------------------------------------------------------------------------


def spotlighting(tool_input: str, delimiter: str = "^") -> str:
    """
    Microsoft 2024 - Spotlighting/Datamarking.
    Prefixes every word in untrusted input with a delimiter character.
    The LLM sees ^ignore ^all ^previous ^instructions instead of a clean command.
    Reduces ASR from 20%+ to <2% on naive injection attacks.
    Zero dependencies, pure string manipulation.
    """
    return " ".join(f"{delimiter}{word}" for word in tool_input.split())


def canary_trap(tool_input: str) -> tuple[str, str]:
    """
    Injects a unique UUID canary into the tool input context.
    Returns (instrumented_input, canary_token).
    Caller must verify that canary does not appear in agent output.
    If canary appears in output -> agent mixed data and instructions -> BLOCK.
    More robust than hardcoded canary strings.
    """
    canary = f"CANARY-{uuid.uuid4().hex[:12].upper()}"
    instrumented = f"{tool_input} [ref:{canary}]"
    return instrumented, canary


def canary_verify(output: str, canary: str) -> bool:
    """Returns True if injection is detected (canary found in output)."""
    return canary in output


def heuristic_score(tool_input: str) -> float:
    """
    Heuristic classifier gate - no ML, no dependencies.
    Scores input on features that regex kill-switches miss:
    - Base64 encoding patterns
    - ROT13 / Caesar cipher indicators
    - Unicode escape sequences
    - High entropy (obfuscated payloads)
    - Known obfuscation signatures

    Returns a score in [0.0, 1.0] where 1.0 = highly suspicious.
    """
    score = 0.0
    text = tool_input.strip()

    # Base64 pattern: long alphanumeric+/ strings with = padding
    if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        score += 0.35

    # Unicode escape sequences
    if re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", text):
        score += 0.30

    # Hex encoded strings
    if re.search(r"(0x[0-9a-fA-F]{4,}|%[0-9a-fA-F]{2})", text):
        score += 0.25

    # High ratio of special characters (obfuscation signal)
    special_ratio = sum(1 for c in text if not c.isalnum() and c not in " .,;:-_") / max(len(text), 1)
    if special_ratio > 0.3:
        score += 0.20

    # Shannon entropy - high entropy = likely encoded/obfuscated
    if len(text) > 10:
        freq = {c: text.count(c) / len(text) for c in set(text)}
        entropy = -sum(p * math.log2(p) for p in freq.values())
        if entropy > 4.5:
            score += 0.15

    # ROT13 indicator: alternating case or specific patterns
    if re.search(r"[A-Z][a-z][A-Z][a-z]{3,}", text) and len(text) > 20:
        score += 0.10

    return min(score, 1.0)


HEURISTIC_BLOCK_THRESHOLD = 0.50


def classifier_gate(tool_input: str) -> tuple[bool, float]:
    """
    Returns (should_block, score).
    Blocks if heuristic_score >= HEURISTIC_BLOCK_THRESHOLD.
    """
    score = heuristic_score(tool_input)
    return score >= HEURISTIC_BLOCK_THRESHOLD, score


# ---------------------------------------------------------------------------
# Composable hardening wrapper
# ---------------------------------------------------------------------------

def apply_l1_5_hardening(
    agent_id: str,
    tool_name: str,
    tool_input: str,
    interceptor_fn: Callable,
) -> tuple[str, str]:
    """
    Applies L1.5 hardening layers before calling the main security interceptor.

    Pipeline:
      1. input_guard     (existing - called via interceptor_fn)
      2. spotlighting    (NEW - datamark untrusted fields)
      3. classifier_gate (NEW - heuristic encoding detector)
      4. canary_trap     (NEW - inject + verify unique tokens)
      5. interceptor_fn  (existing Stage 1/2/3 pipeline)

    Returns (verdict, reason) same as security_interceptor.
    """
    import sys

    # Layer: classifier_gate - detect obfuscated payloads before spotlighting
    should_block, score = classifier_gate(tool_input)
    if should_block:
        print(f"[L1.5] Classifier gate blocked (score={score:.2f})", file=sys.stderr)
        return "DENY", f"BLOCKED by L1.5 heuristic classifier (score={score:.2f})"

    # Layer: spotlighting - datamark untrusted input
    spotted_input = spotlighting(tool_input)
    print(f"[L1.5] Spotlighting applied", file=sys.stderr)

    # Layer: canary_trap - inject canary into spotted input
    instrumented_input, canary = canary_trap(spotted_input)
    print(f"[L1.5] Canary injected: {canary}", file=sys.stderr)

    # Call main interceptor with hardened input
    verdict, reason = interceptor_fn(agent_id, tool_name, instrumented_input)

    # Canary verification: check if canary leaked into the reason/output
    if canary_verify(reason, canary):
        print(f"[L1.5] Canary trap triggered: {canary}", file=sys.stderr)
        return "DENY", f"BLOCKED by L1.5 canary trap (injection executed, canary={canary})"

    return verdict, reason
