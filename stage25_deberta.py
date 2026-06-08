"""
Stage 2.5: DeBERTa fast gate for the UNCERTAIN zone.
Sits between Stage 2 (TF-IDF) and Stage 3 (LLM).
"""
from __future__ import annotations
import re
import os
import sys
import unicodedata

_MODEL = None

_BASE_MODEL = "deepset/deberta-v3-base-injection"
_FT_MODEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "deberta-v3-injection-ft")
# Prefer the fine-tuned model (FPR ~1%) when present. The HF base model has ~91% FPR
# on instruction-format traffic and must not be the silent production default.
_DEFAULT_MODEL = _FT_MODEL if os.path.isdir(_FT_MODEL) else _BASE_MODEL

def _get_model():
    global _MODEL
    if _MODEL is None:
        from transformers import pipeline
        model_name_or_path = os.environ.get("ASF_STAGE25_MODEL", "") or _DEFAULT_MODEL
        if model_name_or_path == _BASE_MODEL:
            print(
                "[ASF WARNING] Stage 2.5 is using the base model "
                f"'{_BASE_MODEL}' which has ~91% FPR on instruction-format traffic. "
                "Provide the fine-tuned model at models/deberta-v3-injection-ft "
                "or set ASF_STAGE25_MODEL for production use.",
                file=sys.stderr,
            )
        _MODEL = pipeline(
            "text-classification",
            model=model_name_or_path,
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


def _classify_scored(tool_input: str) -> tuple[str, float]:
    """
    Returns ("DANGEROUS" | "SAFE" | "UNCERTAIN", injection_probability).
    Strips spotlighting ^ prefix before classification since DeBERTa
    is sensitive to those markers.
    Enabled by default. Set ASF_DISABLE_STAGE25=true to disable.
    """
    if os.environ.get("ASF_DISABLE_STAGE25", "").lower() == "true":
        return "UNCERTAIN", 0.0
    if os.environ.get("ASF_SKIP_STAGE25", "").lower() == "true":
        return "UNCERTAIN", 0.0
    try:
        model = _get_model()
        if model is None:
            return "UNCERTAIN", 0.0
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
        clean = unicodedata.normalize('NFKC', clean)
        result = model(clean)
        label = result[0]['label']
        score = result[0]['score']
        injection_score = score if label == "INJECTION" else 1.0 - score
        if label == "INJECTION" and score > 0.7:
            return "DANGEROUS", injection_score
        elif label == "LEGIT" and score > 0.85:
            return "SAFE", injection_score
        return "UNCERTAIN", injection_score
    except Exception as e:
        print(f"[STAGE 2.5] Error: {e}", file=sys.stderr)
        return "UNCERTAIN", 0.0


def classify(tool_input: str) -> str:
    """
    Returns "DANGEROUS", "SAFE", or "UNCERTAIN".
    """
    verdict, _ = _classify_scored(tool_input)
    return verdict


def classify_text(text: str) -> str:
    return classify(text)


def classify_text_scored(text: str) -> tuple[str, float]:
    return _classify_scored(text)


try:
    warm_up()
except Exception as e:
    print(f"[STAGE 2.5] DeBERTa warm-up skipped: {e}", file=sys.stderr)

def reset_cache():
    """Force reload of the model on next call."""
    global _MODEL
    _MODEL = None
