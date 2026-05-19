"""
Stage 2.5: DeBERTa fast gate for the UNCERTAIN zone.
Sits between Stage 2 (TF-IDF) and Stage 3 (LLM).
"""
from __future__ import annotations
import re
import os
import sys

_MODEL = None

def _get_model():
    global _MODEL
    if _MODEL is None:
        from transformers import pipeline
        _MODEL = pipeline(
            "text-classification",
            model="deepset/deberta-v3-base-injection",
            device=-1
        )
    return _MODEL


def warm_up():
    if os.environ.get("ASF_DISABLE_STAGE25", "").lower() == "true":
        return
    if os.environ.get("ASF_SKIP_STAGE25", "").lower() == "true":
        return
    model = _get_model()
    if model is not None:
        model("test")
        print("[STAGE 2.5] DeBERTa warm-up complete", file=sys.stderr)


def classify(tool_input: str) -> str:
    """
    Returns "DANGEROUS", "SAFE", or "UNCERTAIN".
    Strips spotlighting ^ prefix before classification since DeBERTa
    is sensitive to those markers.
    Enabled by default. Set ASF_DISABLE_STAGE25=true to disable.
    """
    if os.environ.get("ASF_DISABLE_STAGE25", "").lower() == "true":
        return "UNCERTAIN"
    if os.environ.get("ASF_SKIP_STAGE25", "").lower() == "true":
        return "UNCERTAIN"
    try:
        model = _get_model()
        if model is None:
            return "UNCERTAIN"
        # Strip spotlight markers and L1.5 canary references so DeBERTa
        # sees the same clean text whether called directly or via hardened_interceptor.
        clean = re.sub(r'\^', '', tool_input)
        clean = re.sub(r'\s*\[ref:CT-[0-9a-f]+\]\s*', ' ', clean)
        # When tool_input is built as "scenario.message {json_args}", DeBERTa
        # misclassifies the combined text because the imperative prefix + JSON
        # structure triggers injection patterns even for benign content.
        # Extract only the actual string values from JSON key-value pairs so
        # DeBERTa classifies the semantic payload, not the structural wrapper.
        json_values = re.findall(r'"[^"]+"\s*:\s*"([^"]*)"', clean)
        if json_values:
            clean = ' '.join(json_values)
        else:
            clean = re.sub(r'\s+', ' ', clean).strip()
        result = model(clean)
        label = result[0]['label']
        score = result[0]['score']
        if label == "INJECTION" and score > 0.7:
            return "DANGEROUS"
        elif label == "LEGIT" and score > 0.85:
            return "SAFE"
        return "UNCERTAIN"
    except Exception as e:
        print(f"[STAGE 2.5] Error: {e}", file=sys.stderr)
        return "UNCERTAIN"


try:
    warm_up()
except Exception as e:
    print(f"[STAGE 2.5] DeBERTa warm-up skipped: {e}", file=sys.stderr)

def reset_cache():
    """Force reload of the model on next call."""
    global _MODEL
    _MODEL = None
