from __future__ import annotations

import json
import os
import hashlib
from collections import OrderedDict
from typing import Any, Mapping

from secret_redaction import redact_text, redact_value

SCHEMA = 1
MAX_INPUT_CHARS = 2000


def normalize_input(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _json_default(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return repr(value)


def canonical_json(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=_json_default)


def input_id(value: Any) -> str:
    text = canonical_json(value)
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _norm(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        return round(value, 4)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        upper = value.upper()
        if upper in {"ALLOW", "DENY", "UNCERTAIN", "HITL", "SAFE", "DANGEROUS", "UNAVAILABLE"}:
            return upper
        return value
    if isinstance(value, Mapping):
        return OrderedDict((str(k), _norm(value[k])) for k in sorted(value.keys(), key=str))
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    return str(value)


def log(op: str, impl: str, raw_input: Any, out: Mapping[str, Any]) -> None:
    path = os.environ.get("ASF_CANONICAL_LOG")
    if not path:
        return
    text = redact_text(normalize_input(raw_input))
    record = OrderedDict([
        ("op", op),
        ("impl", impl),
        ("input_id", input_id(raw_input)),
        ("input", text[:MAX_INPUT_CHARS]),
        ("out", _norm(redact_value(out))),
        ("schema", SCHEMA),
    ])
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    except Exception:
        # Logging is strictly additive instrumentation. Never affect decisions.
        pass
