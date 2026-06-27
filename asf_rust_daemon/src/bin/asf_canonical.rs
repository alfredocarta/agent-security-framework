#[path = "../audit.rs"]
mod audit;
#[path = "../canonical_log.rs"]
mod canonical_log;
#[path = "../db.rs"]
mod db;
#[path = "../forwarder.rs"]
mod forwarder;
#[path = "../hardening.rs"]
mod hardening;
#[path = "../interceptor.rs"]
mod interceptor;
#[path = "../key_authority.rs"]
mod key_authority;
#[path = "../output_guard.rs"]
mod output_guard;
#[path = "../protocol.rs"]
mod protocol;
#[path = "../registry.rs"]
mod registry;
#[path = "../trace_preview.rs"]
mod trace_preview;
#[path = "../validator.rs"]
mod validator;

use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize)]
struct Entry {
    id: String,
    tool_name: String,
    tool_input: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let corpus_path = PathBuf::from(
        args.get(1)
            .cloned()
            .unwrap_or_else(|| "../tests/equivalence/corpus.jsonl".to_string()),
    );
    let out_dir = PathBuf::from(
        args.get(2)
            .cloned()
            .unwrap_or_else(|| "../tests/equivalence/out".to_string()),
    );
    fs::create_dir_all(&out_dir)?;
    let log_path = out_dir.join("rust_canonical.jsonl");
    let _ = fs::remove_file(&log_path);
    env::set_var("ASF_CANONICAL_LOG", &log_path);
    env::set_var("ASF_ENV", "test");
    env::set_var("ASF_TEST_DB", out_dir.join("equivalence.db"));
    env::set_var("ASF_ROOT", PathBuf::from("..").canonicalize()?);
    env::set_var("ASF_EQUIV_CANARY", "CT-equivalence");

    let corpus_text = fs::read_to_string(&corpus_path)?;
    let corpus: Vec<Entry> = corpus_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let all_tools = corpus
        .iter()
        .map(|e| Value::String(e.tool_name.clone()))
        .collect::<Vec<_>>();
    let permissions = Value::Array(all_tools);
    let pool = Arc::new(registry::open_db(&db::resolve_db_path()));
    for e in &corpus {
        let agent_id = format!("equiv-{}", e.id);
        registry::add_or_update_agent(&pool, &agent_id, "equivalence", &permissions)?;
        let text = e.tool_input.as_str();
        let probe = interceptor::_semantic_probe(text);
        let _ = interceptor::_stage1_regex(text);
        let _ = interceptor::_heuristic_fastpath(&agent_id, &e.tool_name, text, probe);
        let _ = hardening::classify_text(text);
        let _ = hardening::classifier_gate_score(text);
        let _ = hardening::classifier_gate(text);
        let _ = output_guard::check_output(text, "CT-test");
        let _ = trace_preview::output_preview_text(&json!({"content": text, "exit_code": 0}), 512);
        let _ = interceptor::security_interceptor(&agent_id, &e.tool_name, text);
        let _ = registry::reinstate_agent(&pool, &agent_id);
        let _ = interceptor::hardened_interceptor(&agent_id, &e.tool_name, text);
        let _ = registry::reinstate_agent(&pool, &agent_id);
    }

    write_pattern_report(&out_dir, &corpus)?;
    println!("rust canonical log: {}", log_path.display());
    Ok(())
}

fn write_pattern_report(
    out_dir: &PathBuf,
    corpus: &[Entry],
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = Arc::new(registry::open_db(&db::resolve_db_path()));
    let mut rows: Vec<Value> = Vec::new();
    if let Some(Value::Array(patterns)) = registry::get_detection_patterns(&pool)? {
        let canonical = serde_json::to_string(&Value::Array(patterns.clone()))?;
        let digest = Sha256::digest(canonical.as_bytes());
        let hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        fs::write(out_dir.join("rust_pattern_hash.txt"), format!("{hash}\n"))?;
        for pat in patterns.iter().filter_map(|v| v.as_str()) {
            rows.push(pattern_row("db", pat, corpus));
        }
    }
    // Keep this list in sync with interceptor::_RE_SEMANTIC_PROBE; the diff treats
    // missing/compile-failed Rust patterns as critical.
    let semantic = [
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
    ];
    for pat in semantic {
        rows.push(pattern_row("semantic", pat, corpus));
    }
    fs::write(
        out_dir.join("rust_patterns.json"),
        serde_json::to_string_pretty(&rows)?,
    )?;
    Ok(())
}

fn pattern_row(source: &str, pattern: &str, corpus: &[Entry]) -> Value {
    match Regex::new(pattern) {
        Ok(rx) => {
            json!({"source": source, "pattern": pattern, "rust_compiles": true, "rust_matches": corpus.iter().filter(|e| rx.is_match(&e.tool_input)).map(|e| e.id.clone()).collect::<Vec<_>>() })
        }
        Err(err) => {
            json!({"source": source, "pattern": pattern, "rust_compiles": false, "rust_error": err.to_string(), "rust_matches": []})
        }
    }
}
