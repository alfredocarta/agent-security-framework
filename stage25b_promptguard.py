"""
Stage 2.5b: Prompt Guard-style injection specialist gate.

Primary model is Meta Llama Prompt Guard 2 86M. If it is gated or otherwise
unavailable, fall back to the open ProtectAI DeBERTa injection detector.
This stage must never break the pipeline; failures return UNAVAILABLE.
"""
from __future__ import annotations

import os
import re
import sys
import unicodedata

_MODEL = None
_MODEL_ID = None
_LOAD_ATTEMPTED = False

_CANDIDATE_MODELS = (
    "meta-llama/Llama-Prompt-Guard-2-86M",
    "ProtectAI/deberta-v3-base-prompt-injection-v2",
)


def _clean_text(text: str) -> str:
    clean = re.sub(r'\^', '', str(text))
    clean = re.sub(r'\s*\[ref:CT-[0-9a-f]+\]\s*', ' ', clean)
    json_values = re.findall(r'"[^"]+"\s*:\s*"([^"]*)"', clean)
    if json_values:
        clean = ' '.join(json_values)
    else:
        clean = re.sub(r'\s+', ' ', clean).strip()
    return unicodedata.normalize('NFKC', clean)


def _get_model():
    global _MODEL, _MODEL_ID, _LOAD_ATTEMPTED
    if _LOAD_ATTEMPTED:
        return _MODEL
    _LOAD_ATTEMPTED = True
    if os.environ.get("ASF_DISABLE_STAGE25B", "").lower() == "true":
        return None

    from transformers import pipeline

    for model_id in _CANDIDATE_MODELS:
        try:
            _MODEL = pipeline("text-classification", model=model_id, device=-1)
            _MODEL_ID = model_id
            print(f"[STAGE 2.5b] Loaded {model_id}", file=sys.stderr)
            return _MODEL
        except Exception as exc:
            print(f"[STAGE 2.5b] Could not load {model_id}: {exc}", file=sys.stderr)
    _MODEL = None
    _MODEL_ID = None
    return None


def _map_result(result) -> str:
    item = result[0] if isinstance(result, list) else result
    label = str(item.get("label", "")).upper()
    score = float(item.get("score", 0.0))

    if any(token in label for token in ("INJECTION", "DANGEROUS", "JAILBREAK", "MALICIOUS")):
        return "DANGEROUS" if score >= 0.7 else "UNCERTAIN"
    if any(token in label for token in ("LEGIT", "SAFE", "BENIGN")):
        return "SAFE" if score >= 0.85 else "UNCERTAIN"
    return "UNCERTAIN"


def classify_text(text: str) -> str:
    if os.environ.get("ASF_DISABLE_STAGE25B", "").lower() == "true":
        return "UNAVAILABLE"
    try:
        model = _get_model()
        if model is None:
            return "UNAVAILABLE"
        return _map_result(model(_clean_text(text)))
    except Exception as exc:
        print(f"[STAGE 2.5b] Error: {exc}", file=sys.stderr)
        return "UNAVAILABLE"


def warm_up():
    if os.environ.get("ASF_DISABLE_STAGE25B", "").lower() == "true":
        return
    model = _get_model()
    if model is not None:
        model("test")
        print("[STAGE 2.5b] Prompt Guard warm-up complete", file=sys.stderr)


try:
    warm_up()
except Exception as exc:
    print(f"[STAGE 2.5b] Warm-up skipped: {exc}", file=sys.stderr)


def reset_cache():
    global _MODEL, _MODEL_ID, _LOAD_ATTEMPTED
    _MODEL = None
    _MODEL_ID = None
    _LOAD_ATTEMPTED = False
