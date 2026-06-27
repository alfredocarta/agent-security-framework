use crate::audit::{AuditEvent, AuditTrail};
use crate::canonical_log;
use crate::db;
use crate::hardening::{self, InterceptorFn};
use crate::protocol::Verdict;
use crate::registry::{self, DbPool};
use regex::Regex;
use serde_json::json;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

const HEURISTIC_CLEAR_THRESHOLD: f64 = 0.02;
const HEURISTIC_BLOCK_THRESHOLD: f64 = 0.50;

// ── Global DB pool (opened lazily from the same path used by the rest of the daemon) ──

static DB_POOL: OnceLock<Arc<DbPool>> = OnceLock::new();

fn db_pool() -> &'static Arc<DbPool> {
    DB_POOL.get_or_init(|| {
        let path = db::resolve_db_path();
        Arc::new(registry::open_db(&path))
    })
}

fn auditor() -> AuditTrail {
    AuditTrail::new(Arc::clone(db_pool()))
}

// ── Semantic probe patterns ──

static RE_SEMANTIC_PROBE: OnceLock<Vec<Regex>> = OnceLock::new();

fn semantic_probe_patterns() -> &'static Vec<Regex> {
    RE_SEMANTIC_PROBE.get_or_init(|| {
        compile_patterns(&[
            r"(?i)\byou are now\b.{0,30}\b(an? |the )?(ai|assistant|bot|agent|character|persona|role)\b",
            r"(?i)\bact (as|like)\b.{0,50}\b(ai|assistant|bot|agent|model|gpt|claude|chatgpt|llm|dan|character|persona)\b",
            r"(?i)\bpretend (to be|you are|you're)\b",
            r"(?i)\broleplay as\b.{0,60}\b(without|ignoring|bypass|uncensored|unrestricted|no rules|dan|jailbreak)\b",
            r"(?i)\bwithout (any )?(restrictions?|guidelines?|limits?|rules?)\b",
            r"(?i)\bignore (your )?(previous |prior |all |everything )?(instructions?|training|guidelines?|rules?|prompt|above|safety policy|system message)\b",
            r"(?i)\bforget (your |all )?(previous |prior )?(instructions?|training|guidelines?|rules?)\b",
            r"(?i)\boverride (your )?(instructions?|system prompt?|guidelines?|developer message)\b",
            r"(?i)\b(simulate|run as|operate as) (an? )?(unrestricted|uncensored|unfiltered|jailbroken) (ai|model|assistant|chatbot|llm|mode|version)\b",
            r"(?i)\b(disable|turn off|remove|bypass) your (safety|content filter|restrictions?|guardrails?|alignment)\b",
            r"(?i)\b(from now on|starting now)[,\s].{0,60}(you (are|will|should|must)|your (task|role|job))\b",
            r"(?i)\byour (new |actual |real |true )(task|role|instructions?|objective|purpose)\b",
            r"(?i)\bdo not (follow|obey|adhere to)\b",
            r"(?i)\b(disregard|bypass|circumvent) (your |all |any )?(instructions?|rules?|guidelines?|training)\b",
            r"(?i)\b(reveal|show|print|output|repeat|display|write out).{0,30}\b(system prompt|system message|initial prompt|instructions)\b",
            r"(?i)\b(enable|activate|unlock|turn on).{0,20}\b(developer mode|jailbreak|unrestricted|no.?filter|dan)\b",
            r"<\|im_(start|end|sep)\|>|<\|system\|>|\[INST\]|\[/INST\]|<<SYS>>",
            r"(?i)\bnow you are\b\s{0,5}\b[a-zA-Z]",
            r"(?i)^you are\s{0,5}(?:an? |the )?\w+.{0,120}\b(dan|jailbreak|uncensored|unrestricted|no rules|cannot refuse|do anything|ignore policy|developer mode|content policy|not chatgpt|openai rules)\b",
            r"(?i)\byou are\s{0,5}(?:an? |the )?(?:[A-Z][a-z]+).*\?",
            r"(?i)(?:film|movie|scene|play|actor|character|role).{0,80}(?:asks?|says?|speaks?|in their roles|stay in character)",
            r"(?i)(?:two people|actors).{0,80}(?:in their roles|stay in character|breaking character)",
            r"(?i)(?:character|person).{0,30}is (?:the |a )?(?:master|hacker|thief|expert).{0,30}(?:asks?|says?)",
            r"(?i)(?:excellent|great|well done|fantastic|outdone).{0,30}\bnow\b.{0,30}\b(task|help|question|answer)",
            r"(?i)\bthat is (?:done|enough|finished)\b.{0,30}\bnow\b.{0,30}(?:write|answer|help)",
            r"(?i)\bexploiting (?:AI|AI systems|this system)\b",
            r"(?i)(?:spanish|french|german|italian).{0,20}(?:input|output).{0,20}(?:input|output)",
            r"(?im)^\s*(system|developer|assistant)\s*:\s*.{0,80}\b(ignore|override|disregard|reveal|bypass)\b",
        ])
    })
}

pub fn _semantic_probe(text: &str) -> bool {
    let fired = if std::env::var("ASF_DISABLE_SEMANTIC_PROBE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        false
    } else {
        semantic_probe_patterns()
            .iter()
            .any(|pattern| pattern.is_match(text))
    };
    canonical_log::log("semantic_probe", "rust", text, json!({"fired": fired}));
    fired
}

// ── Stage 1: DB-backed regex engine ──

pub fn _stage1_regex(tool_input: &str) -> Result<(bool, Option<String>), String> {
    let pool = db_pool();
    let patterns = registry::get_detection_patterns(pool)
        .map_err(|e| format!("DB error loading detection patterns: {e}"))?;

    let patterns = match patterns {
        Some(v) => v,
        None => return Ok((false, None)),
    };

    let pattern_list = patterns
        .as_array()
        .ok_or_else(|| "detection_patterns is not a JSON array".to_string())?;

    for pattern_val in pattern_list {
        let pattern_text = pattern_val
            .as_str()
            .ok_or_else(|| format!("non-string pattern: {pattern_val}"))?;
        let re = Regex::new(pattern_text)
            .map_err(|e| format!("invalid detection regex {pattern_text:?}: {e}"))?;
        if re.is_match(tool_input) {
            canonical_log::log(
                "stage1_regex",
                "rust",
                tool_input,
                json!({"matched": true, "pattern": pattern_text}),
            );
            return Ok((true, Some(pattern_text.to_string())));
        }
    }
    canonical_log::log(
        "stage1_regex",
        "rust",
        tool_input,
        json!({"matched": false, "pattern": null}),
    );
    Ok((false, None))
}

// ── Heuristic fast-path (L1.5 gate, Stage 1.5) ──

pub fn _heuristic_fastpath(
    agent_id: &str,
    tool_name: &str,
    tool_input: &str,
    probe_fired: bool,
) -> Option<(String, String)> {
    if std::env::var("ASF_DISABLE_FASTPATH")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return None;
    }

    let clear_threshold = std::env::var("ASF_CLEAR_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(HEURISTIC_CLEAR_THRESHOLD);
    let block_threshold = std::env::var("ASF_HEURISTIC_BLOCK")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(HEURISTIC_BLOCK_THRESHOLD);

    let score = hardening::classifier_gate_score(tool_input);
    let auditor = auditor();

    if score >= block_threshold {
        let score_pct = format!("{:.0}%", score * 100.0);
        let _ = auditor.log_event(AuditEvent::new(
            agent_id,
            tool_name,
            "HEURISTIC_BLOCK",
            format!("Blocked by heuristic fast-path (score={score_pct})"),
        ));
        let result = (
            "DENY".to_string(),
            format!("BLOCKED by heuristic (score={score_pct})"),
        );
        canonical_log::log(
            "heuristic_fastpath",
            "rust",
            tool_input,
            json!({"verdict": result.0, "reason": result.1}),
        );
        return Some(result);
    }

    let always_stage25 = std::env::var("ASF_ALWAYS_STAGE25")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if score <= clear_threshold && !always_stage25 {
        if probe_fired {
            let _ = auditor.log_event(AuditEvent::new(
                agent_id,
                tool_name,
                "SEMANTIC_PROBE_ESCALATE",
                format!(
                    "Semantic probe triggered on heuristic-clear candidate (score={score:.2}), escalating to pipeline"
                ),
            ));
            canonical_log::log(
                "heuristic_fastpath",
                "rust",
                tool_input,
                json!({"verdict": null, "reason": null}),
            );
            return None;
        }
        let score_pct = format!("{:.0}%", score * 100.0);
        let _ = auditor.log_event(AuditEvent::new(
            agent_id,
            tool_name,
            "HEURISTIC_CLEAR",
            format!("Cleared by heuristic fast-path ({score_pct})"),
        ));
        let result = (
            "ALLOW".to_string(),
            format!("Cleared by heuristic ({score_pct})"),
        );
        canonical_log::log(
            "heuristic_fastpath",
            "rust",
            tool_input,
            json!({"verdict": result.0, "reason": result.1}),
        );
        return Some(result);
    }

    canonical_log::log(
        "heuristic_fastpath",
        "rust",
        tool_input,
        json!({"verdict": null, "reason": null}),
    );
    None
}

fn _heuristic_fastpath_with_score(
    agent_id: &str,
    tool_name: &str,
    tool_input: &str,
    probe_fired: bool,
    score: f64,
) -> Option<(String, String)> {
    if std::env::var("ASF_DISABLE_FASTPATH")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return None;
    }

    let clear_threshold = std::env::var("ASF_CLEAR_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(HEURISTIC_CLEAR_THRESHOLD);
    let block_threshold = std::env::var("ASF_HEURISTIC_BLOCK")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(HEURISTIC_BLOCK_THRESHOLD);
    let auditor = auditor();

    if score >= block_threshold {
        let score_pct = format!("{:.0}%", score * 100.0);
        let _ = auditor.log_event(AuditEvent::new(
            agent_id,
            tool_name,
            "HEURISTIC_BLOCK",
            format!("Blocked by heuristic fast-path (score={score_pct})"),
        ));
        let result = (
            "DENY".to_string(),
            format!("BLOCKED by heuristic (score={score_pct})"),
        );
        canonical_log::log(
            "heuristic_fastpath",
            "rust",
            tool_input,
            json!({"verdict": result.0, "reason": result.1}),
        );
        return Some(result);
    }

    let always_stage25 = std::env::var("ASF_ALWAYS_STAGE25")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if score <= clear_threshold && !always_stage25 {
        if probe_fired {
            let _ = auditor.log_event(AuditEvent::new(
                agent_id,
                tool_name,
                "SEMANTIC_PROBE_ESCALATE",
                format!(
                    "Semantic probe triggered on heuristic-clear candidate (score={score:.2}), escalating to pipeline"
                ),
            ));
            canonical_log::log(
                "heuristic_fastpath",
                "rust",
                tool_input,
                json!({"verdict": null, "reason": null}),
            );
            return None;
        }
        let score_pct = format!("{:.0}%", score * 100.0);
        let _ = auditor.log_event(AuditEvent::new(
            agent_id,
            tool_name,
            "HEURISTIC_CLEAR",
            format!("Cleared by heuristic fast-path ({score_pct})"),
        ));
        let result = (
            "ALLOW".to_string(),
            format!("Cleared by heuristic ({score_pct})"),
        );
        canonical_log::log(
            "heuristic_fastpath",
            "rust",
            tool_input,
            json!({"verdict": result.0, "reason": result.1}),
        );
        return Some(result);
    }

    canonical_log::log(
        "heuristic_fastpath",
        "rust",
        tool_input,
        json!({"verdict": null, "reason": null}),
    );
    None
}

// ── security_interceptor: Stage 1 + handoff to Python for Stage 2/3 ──

pub fn extract_tool_input_text(tool_input: &serde_json::Value) -> String {
    for key in [
        "command",
        "new_string",
        "new_source",
        "content",
        "pattern",
        "prompt",
        "file_path",
        "path",
    ] {
        if let Some(value) = tool_input[key].as_str() {
            return value.to_string();
        }
    }

    serde_json::to_string(tool_input).unwrap_or_default()
}

pub fn check_value(tool_input: &serde_json::Value) -> (Verdict, String, String, String) {
    let extracted_text = extract_tool_input_text(tool_input);
    let (outcome, reason) = security_interceptor("rust_daemon", "tool_input", &extracted_text);

    let verdict = match outcome.as_str() {
        "DENY" => Verdict::Deny,
        "ALLOW" => Verdict::Allow,
        _ => Verdict::Uncertain,
    };

    let db_outcome = match verdict {
        Verdict::Deny if reason.contains("Stage 1 regex") => "KILL_SWITCH".to_string(),
        Verdict::Deny if reason.contains("heuristic") => "HEURISTIC_BLOCK".to_string(),
        Verdict::Deny if reason.contains("Stage 1 regex engine error") => {
            "STAGE1_ERROR".to_string()
        }
        Verdict::Deny => outcome,
        _ => String::new(),
    };

    (verdict, reason, db_outcome, extracted_text)
}

pub fn security_interceptor(agent_id: &str, tool_name: &str, tool_input: &str) -> (String, String) {
    security_interceptor_inner(agent_id, tool_name, tool_input, None)
}

fn security_interceptor_inner(
    agent_id: &str,
    tool_name: &str,
    tool_input: &str,
    l15_context: Option<(bool, f64)>,
) -> (String, String) {
    let _start = Instant::now();
    let auditor = auditor();
    let pool = db_pool();

    let probe_fired = match l15_context {
        Some((probe, _score)) => probe,
        None => _semantic_probe(tool_input),
    };
    let fastpath_result = _heuristic_fastpath(agent_id, tool_name, tool_input, probe_fired);
    if let Some(result) = fastpath_result {
        canonical_log::log(
            "security_interceptor",
            "rust",
            tool_input,
            json!({"verdict": result.0, "reason": result.1}),
        );
        return result;
    }

    match _stage1_regex(tool_input) {
        Ok((true, pattern)) => {
            let matched = pattern.unwrap_or_else(|| "<unknown>".to_string());
            let _ = registry::suspend_agent(pool, agent_id);
            let _ = auditor.log_event(AuditEvent::new(
                agent_id,
                tool_name,
                "KILL_SWITCH",
                format!("Stage 1 regex matched: {matched}"),
            ));
            let result = (
                "DENY".to_string(),
                format!("BLOCKED by Stage 1 regex: {matched}"),
            );
            canonical_log::log(
                "security_interceptor",
                "rust",
                tool_input,
                json!({"verdict": result.0, "reason": result.1}),
            );
            return result;
        }
        Ok((false, _)) => {}
        Err(err) => {
            let _ = auditor.log_event(AuditEvent::new(agent_id, tool_name, "STAGE1_ERROR", &err));
            let result = (
                "DENY".to_string(),
                format!("Stage 1 regex engine error: {err}"),
            );
            canonical_log::log(
                "security_interceptor",
                "rust",
                tool_input,
                json!({"verdict": result.0, "reason": result.1}),
            );
            return result;
        }
    }

    if probe_fired {
        let _ = auditor.log_event(AuditEvent::new(
            agent_id,
            tool_name,
            "SEMANTIC_PROBE_ESCALATE",
            "Semantic probe triggered; requires Python Stage 2/3 adjudication",
        ));
    }

    // PYTHON PIPELINE BOUNDARY: Rust stops here. The caller must forward to the
    // existing Python pipeline for Stage 2 (sklearn), Stage 2.5, and Stage 3 (LLM/ONNX).
    // Suggested Unix-socket newline-delimited JSON request:
    //   { "type":"stage23_check", "agent_id":..., "tool_name":..., "input":...,
    //     "trace_id":..., "source":"rust_interceptor" }
    // Expected response:
    //   { "verdict":"ALLOW|DENY", "reason":"...", "audit_hash":"..." }
    let result = (
        "UNCERTAIN".to_string(),
        "stage1_no_match_forward_to_python_stage23".to_string(),
    );
    canonical_log::log(
        "security_interceptor",
        "rust",
        tool_input,
        json!({"verdict": result.0, "reason": result.1}),
    );
    result
}

// ── hardened_interceptor: L1.5 → Stage 1 → Python Stage 2/3 ──

pub fn hardened_interceptor(
    agent_id: &str,
    tool_name: &str,
    tool_input: &str,
) -> (String, String, Option<String>) {
    let probe_fired = _semantic_probe(tool_input);
    let l15_score = hardening::classifier_gate_score(tool_input);
    let interceptor_fn: InterceptorFn = Box::new(move |a, t, i| {
        security_interceptor_inner(a, t, i, Some((probe_fired, l15_score)))
    });
    let result =
        hardening::apply_l1_5_hardening(agent_id, tool_name, tool_input, Some(interceptor_fn));
    canonical_log::log(
        "hardened_interceptor",
        "rust",
        tool_input,
        json!({"verdict": result.0, "reason": result.1}),
    );
    result
}

fn compile_patterns(patterns: &[&str]) -> Vec<Regex> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).unwrap_or_else(|err| {
                panic!("failed to compile semantic-probe regex {pattern:?}: {err}");
            })
        })
        .collect()
}
