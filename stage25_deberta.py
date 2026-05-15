"""
Stage 2.5: DeBERTa fast gate for the UNCERTAIN zone.
Sits between Stage 2 (TF-IDF) and Stage 3 (LLM).
"""
from __future__ import annotations
import re
import os

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


def classify(tool_input: str) -> str:
    """
    Returns "DANGEROUS", "SAFE", or "UNCERTAIN".
    Strips spotlighting ^ prefix before classification since DeBERTa
    is sensitive to those markers.
    Disabled by default. Set ASF_ENABLE_STAGE25=true to activate.
    """
    if os.environ.get("ASF_ENABLE_STAGE25", "").lower() != "true":
        return "UNCERTAIN"
    if os.environ.get("ASF_SKIP_STAGE25", "").lower() == "true":
        return "UNCERTAIN"
    try:
        model = _get_model()
        if model is None:
            return "UNCERTAIN"
        # Strip spotlight markers
        clean = re.sub(r'\^', '', tool_input)
        result = model(clean)
        label = result[0]['label']
        score = result[0]['score']
        if label == "INJECTION" and score > 0.7:
            return "DANGEROUS"
        elif label == "LEGIT" and score > 0.85:
            return "SAFE"
        return "UNCERTAIN"
    except Exception as e:
        import sys
        print(f"[STAGE 2.5] Error: {e}", file=sys.stderr)
        return "UNCERTAIN"


# Pre-load model on import (non-blocking, cached after first call)
def _preload():
    import os
    if os.environ.get("ASF_ENABLE_STAGE25", "").lower() != "true":
        return  # Disabled by default
    try:
        _get_model()
    except Exception:
        pass

_preload()

def reset_cache():
    """Force reload of the model on next call."""
    global _MODEL
    _MODEL = None
