#!/usr/bin/env python3
from __future__ import annotations
import json, os, pathlib, sys, re, hashlib
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
out_dir = pathlib.Path(os.environ.get("ASF_EQUIV_OUT", ROOT/"tests/equivalence/out"))
out_dir.mkdir(parents=True, exist_ok=True)
log = out_dir/"py_canonical.jsonl"
if log.exists(): log.unlink()
db_path = out_dir/"equivalence.db"
os.environ.update({
    "ASF_CANONICAL_LOG": str(log), "ASF_ENV":"test", "ASF_ROOT": str(ROOT),
    "ASF_TEST_DB": str(db_path), "DATABASE_URL": "sqlite:///"+str(db_path),
    "ASF_DISABLE_STAGE25":"true", "ASF_SKIP_LLM":"true",
    "ASF_EQUIV_CANARY":"CT-equivalence",
})
try: db_path.unlink()
except FileNotFoundError: pass
import migrate_policies
migrate_policies.migrate()
import registry, canonical_log
from interceptor import _semantic_probe, _stage1_regex, _heuristic_fastpath, security_interceptor, hardened_interceptor, _RE_SEMANTIC_PROBE
import hardening, output_guard, trace_output_preview
corpus=[json.loads(l) for l in (ROOT/"tests/equivalence/corpus.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
all_tools=sorted({e["tool_name"] for e in corpus})
for e in corpus:
    entry_id=str(e["id"])
    agent_id=f"equiv-{entry_id}"
    registry.add_or_update_agent(agent_id, "equivalence", all_tools)
    text=e["tool_input"]; tool=e["tool_name"]
    _semantic_probe(text); _stage1_regex(text)
    _heuristic_fastpath(agent_id, tool, text, f"trace-{entry_id}", lambda:0, probe_fired=_semantic_probe(text))
    hardening.classify_text(text); hardening._classifier_gate_score(text); hardening.classifier_gate(text)
    output_guard.check_output(text, "CT-test")
    trace_output_preview.output_preview_text({"content": text, "exit_code": 0}, 512)
    # Boundary-only: direct security/hardened calls are intentionally constrained by env and may reach Python-only stages.
    try: security_interceptor(agent_id, tool, text, use_fastpath=True, probe_fired=_semantic_probe(text))
    except Exception as exc: canonical_log.log("security_interceptor", "py", text, {"verdict":"UNCERTAIN", "reason": f"runner_error:{exc}"})
    registry.reinstate_agent(agent_id)
    try: hardened_interceptor(agent_id, tool, text)
    except Exception as exc: canonical_log.log("hardened_interceptor", "py", text, {"verdict":"UNCERTAIN", "reason": f"runner_error:{exc}"})
    registry.reinstate_agent(agent_id)
# Python pattern compile/match snapshot for diff report.
patterns = registry.get_detection_patterns() or []
pattern_report=[]
def pat_row(src, pat, flags=0):
    try:
        rx=re.compile(pat, flags)
        matches=[e["id"] for e in corpus if rx.search(e["tool_input"])]
        return {"source":src,"pattern":pat,"py_flags":int(flags),"py_ignorecase":bool(flags & re.IGNORECASE),"py_compiles":True,"py_matches":matches}
    except Exception as exc:
        return {"source":src,"pattern":pat,"py_flags":int(flags),"py_ignorecase":bool(flags & re.IGNORECASE),"py_compiles":False,"py_error":str(exc),"py_matches":[]}
for pat in patterns:
    pattern_report.append(pat_row("db", pat))
for p in _RE_SEMANTIC_PROBE:
    pattern_report.append(pat_row("semantic", p.pattern, p.flags))
(out_dir/"py_patterns.json").write_text(json.dumps(pattern_report,ensure_ascii=False,indent=2),encoding="utf-8")
(out_dir/"py_pattern_hash.txt").write_text(hashlib.sha256(json.dumps(patterns, sort_keys=True, separators=(",", ":")).encode()).hexdigest()+"\n", encoding="utf-8")
print(f"python canonical log: {log}")
