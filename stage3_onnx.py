from __future__ import annotations

import sys
import re
import unicodedata

_model = None
_tokenizer = None
_init_attempted = False

INJECTION_LABELS = {"INJECTION", "MALICIOUS", "DANGEROUS", "JAILBREAK", "LABEL_1", "1"}
HIGH_RISK_PATTERNS = (
    re.compile(r"\bsudo\b.*\b(cat|less|more|tail|head|cp|mv|rm|chmod|chown)\b", re.IGNORECASE),
    re.compile(r"/etc/(shadow|sudoers|passwd)\b", re.IGNORECASE),
)


def _get_model():
    global _model, _tokenizer, _init_attempted
    if _init_attempted:
        return _model, _tokenizer
    _init_attempted = True
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        from transformers import AutoTokenizer

        model_id = "gravitee-io/Llama-Prompt-Guard-2-86M-onnx"
        _tokenizer = AutoTokenizer.from_pretrained(model_id)
        _model = ORTModelForSequenceClassification.from_pretrained(model_id)
        print("[STAGE 3 ONNX] Prompt Guard 86M loaded", file=sys.stderr)
    except Exception as e:
        print(f"[STAGE 3 ONNX] 86M failed: {e}", file=sys.stderr)
        try:
            from optimum.onnxruntime import ORTModelForSequenceClassification
            from transformers import AutoTokenizer

            model_id = "gravitee-io/Llama-Prompt-Guard-2-22M-onnx"
            _tokenizer = AutoTokenizer.from_pretrained(model_id)
            _model = ORTModelForSequenceClassification.from_pretrained(model_id)
            print("[STAGE 3 ONNX] Prompt Guard 22M loaded (fallback)", file=sys.stderr)
        except Exception as e2:
            print(f"[STAGE 3 ONNX] Both models failed: {e2}", file=sys.stderr)
    return _model, _tokenizer


def classify_text(text: str) -> str:
    import torch

    model, tokenizer = _get_model()
    if model is None or tokenizer is None:
        return "UNAVAILABLE"
    try:
        text = unicodedata.normalize("NFKC", text)
        if any(pattern.search(text) for pattern in HIGH_RISK_PATTERNS):
            return "DANGEROUS"
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)
        label = model.config.id2label[probs.argmax().item()]
        score = probs.max().item()
        if label.upper() in INJECTION_LABELS and score >= 0.7:
            return "DANGEROUS"
        elif label.upper() in INJECTION_LABELS and score >= 0.4:
            return "UNCERTAIN"
        else:
            return "SAFE"
    except Exception as e:
        print(f"[STAGE 3 ONNX] Inference error: {e}", file=sys.stderr)
        return "UNCERTAIN"


def warm_up():
    try:
        classify_text("test input for warm-up")
        print("[STAGE 3 ONNX] Warm-up complete", file=sys.stderr)
    except Exception:
        pass
