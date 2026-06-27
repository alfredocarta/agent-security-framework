use crate::audit::{AuditEvent, AuditTrail};
use crate::db;
use crate::hardening::{self, InterceptorFn};
use crate::protocol::Verdict;
use crate::registry::{self, DbPool};
use regex::Regex;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

const HEURISTIC_CLEAR_THRESHOLD: f64 = 0.02;
const HEURISTIC_BLOCK_THRESHOLD: f64 = 0.50;

// ── Global DB pool (opened lazily from the same path used by the rest of the daemon) ──

#[cfg(not(test))]
static DB_POOL: OnceLock<Arc<DbPool>> = OnceLock::new();

#[cfg(not(test))]
fn db_pool() -> Arc<DbPool> {
    Arc::clone(DB_POOL.get_or_init(|| {
        let path = db::resolve_db_path();
        Arc::new(registry::open_db(&path))
    }))
}

#[cfg(test)]
fn db_pool() -> Arc<DbPool> {
    let path = db::resolve_db_path();
    Arc::new(registry::open_db(&path))
}

fn auditor() -> AuditTrail {
    let audit = AuditTrail::new(db_pool());
    let _ = audit.ensure_optional_columns();
    audit
}

fn log_audit_event(
    auditor: &AuditTrail,
    agent_id: &str,
    tool_name: &str,
    outcome: &str,
    reason: impl Into<String>,
    session_id: Option<&str>,
    trace_id: Option<&str>,
) {
    let mut event = AuditEvent::new(agent_id, tool_name, outcome, reason.into());
    event.session_id = session_id.map(str::to_string);
    event.trace_id = trace_id.map(str::to_string);
    let _ = auditor.log_event(event);
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
    if std::env::var("ASF_DISABLE_SEMANTIC_PROBE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return false;
    }
    semantic_probe_patterns()
        .iter()
        .any(|pattern| pattern.is_match(text))
}

// ── Stage 1: DB-backed regex engine ──

pub fn _stage1_regex(tool_input: &str) -> Result<(bool, Option<String>), String> {
    let pool = db_pool();
    let patterns = registry::get_detection_patterns(&pool)
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
            return Ok((true, Some(pattern_text.to_string())));
        }
    }
    Ok((false, None))
}

// ── Heuristic fast-path (L1.5 gate, Stage 1.5) ──

pub fn _heuristic_fastpath(
    agent_id: &str,
    tool_name: &str,
    session_id: Option<&str>,
    trace_id: Option<&str>,
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
        log_audit_event(
            &auditor,
            agent_id,
            tool_name,
            "HEURISTIC_BLOCK",
            format!("Blocked by heuristic fast-path (score={score_pct})"),
            session_id,
            trace_id,
        );
        return Some((
            "DENY".to_string(),
            format!("BLOCKED by heuristic (score={score_pct})"),
        ));
    }

    let always_stage25 = std::env::var("ASF_ALWAYS_STAGE25")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if score <= clear_threshold && !always_stage25 {
        if probe_fired {
            log_audit_event(
                &auditor,
                agent_id,
                tool_name,
                "SEMANTIC_PROBE_ESCALATE",
                format!(
                    "Semantic probe triggered on heuristic-clear candidate (score={score:.2}), escalating to pipeline"
                ),
                session_id,
                trace_id,
            );
            return None;
        }
        let score_pct = format!("{:.0}%", score * 100.0);
        log_audit_event(
            &auditor,
            agent_id,
            tool_name,
            "HEURISTIC_CLEAR",
            format!("Cleared by heuristic fast-path ({score_pct})"),
            session_id,
            trace_id,
        );
        return Some((
            "ALLOW".to_string(),
            format!("Cleared by heuristic ({score_pct})"),
        ));
    }

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

fn trace_id_for_call(
    session_id: Option<&str>,
    transcript_path: Option<&str>,
    explicit_tool_call_id: Option<&str>,
    tool_name: &str,
    tool_input: &serde_json::Value,
) -> Option<String> {
    let args_hash = db::compute_args_hash(tool_input);
    let tool_call_id = db::effective_tool_call_id(
        explicit_tool_call_id,
        session_id,
        transcript_path,
        tool_name,
        &args_hash,
    );
    Some(db::compute_trace_id(
        session_id,
        &tool_call_id,
        tool_name,
        &args_hash,
    ))
}

pub fn check_value(
    agent_id: &str,
    tool_name: &str,
    session_id: Option<&str>,
    transcript_path: Option<&str>,
    tool_call_id: Option<&str>,
    tool_input: &serde_json::Value,
) -> (Verdict, String, String, String) {
    let extracted_text = extract_tool_input_text(tool_input);
    let trace_id = trace_id_for_call(
        session_id,
        transcript_path,
        tool_call_id,
        tool_name,
        tool_input,
    );
    let (outcome, reason) = security_interceptor(
        agent_id,
        tool_name,
        session_id,
        trace_id.as_deref(),
        &extracted_text,
    );

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

pub fn security_interceptor(
    agent_id: &str,
    tool_name: &str,
    session_id: Option<&str>,
    trace_id: Option<&str>,
    tool_input: &str,
) -> (String, String) {
    let _start = Instant::now();
    let auditor = auditor();
    let pool = db_pool();

    let probe_fired = _semantic_probe(tool_input);
    match _stage1_regex(tool_input) {
        Ok((true, pattern)) => {
            let matched = pattern.unwrap_or_else(|| "<unknown>".to_string());
            let _ = registry::suspend_agent(&pool, agent_id);
            log_audit_event(
                &auditor,
                agent_id,
                tool_name,
                "KILL_SWITCH",
                format!("Stage 1 regex matched: {matched}"),
                session_id,
                trace_id,
            );
            return (
                "DENY".to_string(),
                format!("BLOCKED by Stage 1 regex: {matched}"),
            );
        }
        Ok((false, _)) => {}
        Err(err) => {
            log_audit_event(
                &auditor,
                agent_id,
                tool_name,
                "STAGE1_ERROR",
                &err,
                session_id,
                trace_id,
            );
            return (
                "DENY".to_string(),
                format!("Stage 1 regex engine error: {err}"),
            );
        }
    }

    if let Some(result) = _heuristic_fastpath(
        agent_id,
        tool_name,
        session_id,
        trace_id,
        tool_input,
        probe_fired,
    ) {
        return result;
    }

    if probe_fired {
        log_audit_event(
            &auditor,
            agent_id,
            tool_name,
            "SEMANTIC_PROBE_ESCALATE",
            "Semantic probe triggered; requires Python Stage 2/3 adjudication",
            session_id,
            trace_id,
        );
    }

    // PYTHON PIPELINE BOUNDARY: Rust stops here. The caller must forward to the
    // existing Python pipeline for Stage 2 (sklearn), Stage 2.5, and Stage 3 (LLM/ONNX).
    // Suggested Unix-socket newline-delimited JSON request:
    //   { "type":"stage23_check", "agent_id":..., "tool_name":..., "input":...,
    //     "trace_id":..., "source":"rust_interceptor" }
    // Expected response:
    //   { "verdict":"ALLOW|DENY", "reason":"...", "audit_hash":"..." }
    (
        "UNCERTAIN".to_string(),
        "stage1_no_match_forward_to_python_stage23".to_string(),
    )
}

// ── hardened_interceptor: L1.5 → Stage 1 → Python Stage 2/3 ──

pub fn hardened_interceptor(
    agent_id: &str,
    tool_name: &str,
    tool_input: &str,
) -> (String, String, Option<String>) {
    let interceptor_fn: InterceptorFn =
        Box::new(|a, t, i| security_interceptor(a, t, None, None, i));
    hardening::apply_l1_5_hardening(agent_id, tool_name, tool_input, Some(interceptor_fn))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CheckRequest;
    use rusqlite::Connection;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("test env lock poisoned")
    }

    fn unique_test_db_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "asf-rust-daemon-attribution-{}-{nanos}.db",
            std::process::id()
        ))
    }

    #[test]
    fn check_value_logs_request_identity_instead_of_placeholders() {
        let _guard = test_env_lock();
        let db_path = unique_test_db_path();
        let db = registry::open_db(&db_path);
        registry::store_detection_patterns(&db, &json!(["ASF_ATTRIBUTION_TEST_SENTINEL"]))
            .expect("store test detection pattern");
        drop(db);

        std::env::set_var("ASF_HOOK_DB", &db_path);

        let tool_input = json!({"command": "echo ASF_ATTRIBUTION_TEST_SENTINEL"});
        let (verdict, reason, db_outcome, _extracted_text) = check_value(
            "claude-code",
            "Bash",
            Some("claude-session-123"),
            Some("/tmp/claude-session-123.jsonl"),
            Some("toolu-stage1-test"),
            &tool_input,
        );

        assert!(matches!(verdict, Verdict::Deny));
        assert!(reason.contains("Stage 1 regex"));
        assert_eq!(db_outcome, "KILL_SWITCH");

        let conn = Connection::open(&db_path).expect("open test db");
        let (agent_id, action, outcome, session_id): (String, String, String, Option<String>) =
            conn.query_row(
                "SELECT agent_id, action, outcome, session_id \
                 FROM audit_trail \
                 WHERE outcome = 'KILL_SWITCH' \
                 ORDER BY timestamp DESC \
                 LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read audit event");

        assert_eq!(agent_id, "claude-code");
        assert_eq!(action, "Bash");
        assert_eq!(outcome, "KILL_SWITCH");
        assert_eq!(session_id.as_deref(), Some("claude-session-123"));

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn fast_path_allow_audit_trace_id_matches_claude_tool_trace() {
        let _guard = test_env_lock();
        let db_path = unique_test_db_path();
        let db = registry::open_db(&db_path);
        registry::store_detection_patterns(&db, &json!([])).expect("store empty test patterns");
        drop(db);

        std::env::set_var("ASF_HOOK_DB", &db_path);
        std::env::remove_var("ASF_DISABLE_FASTPATH");
        std::env::remove_var("ASF_ALWAYS_STAGE25");
        std::env::set_var("ASF_CLEAR_THRESHOLD", "0.02");

        let tool_input = json!({"command": "pwd"});
        let req = CheckRequest {
            tool_name: "Bash".to_string(),
            tool_input: tool_input.clone(),
            session_id: Some("claude-session-fast-allow".to_string()),
            transcript_path: Some("/tmp/claude-session-fast-allow.jsonl".to_string()),
            tool_use_id: Some("toolu-fast-allow".to_string()),
            agent_id: "claude-code".to_string(),
        };

        let (verdict, reason, db_outcome, _extracted_text) = check_value(
            &req.agent_id,
            &req.tool_name,
            req.session_id.as_deref(),
            req.transcript_path.as_deref(),
            req.tool_use_id.as_deref(),
            &req.tool_input,
        );
        assert!(matches!(verdict, Verdict::Allow));
        assert!(reason.contains("heuristic"));
        assert_eq!(db_outcome, "");

        db::write_claude_trace(&db_path, &req, "ALLOW", "HEURISTIC_CLEAR", &reason)
            .expect("write claude trace");

        let conn = Connection::open(&db_path).expect("open test db");
        let (audit_trace_id, terminal_count): (String, i64) = conn
            .query_row(
                "SELECT trace_id, COUNT(*) FROM audit_trail \
                 WHERE outcome = 'HEURISTIC_CLEAR'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read heuristic clear audit trace_id");
        let audit_row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_trail", [], |row| row.get(0))
            .expect("count audit events");
        let start_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_trail WHERE outcome = 'INTERCEPTOR_START'",
                [],
                |row| row.get(0),
            )
            .expect("count interceptor start audit events");
        let (claude_trace_id, claude_trace_count): (String, i64) = conn
            .query_row(
                "SELECT trace_id, COUNT(*) FROM claude_tool_traces \
                 WHERE tool_call_id = 'toolu-fast-allow'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read claude tool trace_id");

        assert_eq!(terminal_count, 1);
        assert_eq!(audit_row_count, 1);
        assert_eq!(start_count, 0);
        assert_eq!(claude_trace_count, 1);
        assert!(!audit_trace_id.is_empty());
        assert_eq!(audit_trace_id, claude_trace_id);

        drop(conn);
        let _ = std::fs::remove_file(db_path);
    }
}
