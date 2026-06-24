use crate::registry::DbPool;
use crate::trace_preview::output_preview_text;
use regex::Regex;
use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use uuid::Uuid;

const DEFAULT_CLAUDE_AGENT_ID: &str = "claude-code-agent";
const DEFAULT_CLAUDE_AGENT_MODEL: &str = "claude-sonnet-4-6 via Claude Code";
const DEFAULT_HERMES_AGENT_ID: &str = "hermes-agent";
const DEFAULT_HERMES_AGENT_TYPE: &str = "hermes-agent";

const CLAUDE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS claude_tool_traces (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'claude-code',
    agent_id TEXT NOT NULL,
    agent_model TEXT,
    session_id TEXT,
    transcript_path TEXT,
    tool_call_id TEXT,
    claude_tool_name TEXT NOT NULL,
    asf_tool_name TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    args_preview TEXT,
    output_hash TEXT,
    output_preview TEXT,
    verdict TEXT,
    outcome TEXT,
    reason TEXT,
    confidence REAL,
    trace_id TEXT,
    audit_hash TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_claude_traces_timestamp ON claude_tool_traces(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_claude_traces_session ON claude_tool_traces(session_id);
CREATE INDEX IF NOT EXISTS idx_claude_traces_tool_call ON claude_tool_traces(tool_call_id);
CREATE INDEX IF NOT EXISTS idx_claude_traces_trace ON claude_tool_traces(trace_id);
CREATE INDEX IF NOT EXISTS idx_claude_traces_audit_hash ON claude_tool_traces(audit_hash);
"#;

const HERMES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS hermes_tool_traces (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'hermes',
    agent_id TEXT NOT NULL,
    agent_type TEXT,
    agent_model TEXT,
    session_id TEXT,
    task_id TEXT,
    tool_call_id TEXT,
    hermes_tool_name TEXT NOT NULL,
    asf_tool_name TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    args_preview TEXT,
    output_hash TEXT,
    output_preview TEXT,
    verdict TEXT,
    outcome TEXT,
    reason TEXT,
    stage TEXT,
    confidence REAL,
    asf_latency_ms INTEGER,
    tool_duration_ms INTEGER,
    side_effect_verified INTEGER DEFAULT 0,
    side_effect_occurred INTEGER,
    expected_label TEXT,
    human_label TEXT,
    scenario_id TEXT,
    threat_id TEXT,
    trace_id TEXT,
    audit_hash TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hermes_traces_timestamp ON hermes_tool_traces(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_hermes_traces_session ON hermes_tool_traces(session_id);
CREATE INDEX IF NOT EXISTS idx_hermes_traces_tool_call ON hermes_tool_traces(tool_call_id);
CREATE INDEX IF NOT EXISTS idx_hermes_traces_verdict ON hermes_tool_traces(verdict);
CREATE INDEX IF NOT EXISTS idx_hermes_traces_threat ON hermes_tool_traces(threat_id);
CREATE INDEX IF NOT EXISTS idx_hermes_traces_source ON hermes_tool_traces(source);
"#;

pub fn resolve_db_path() -> PathBuf {
    if let Some(path) = env::var_os("ASF_HOOK_DB") {
        return PathBuf::from(path);
    }

    if let Ok(database_url) = env::var("DATABASE_URL") {
        if let Some(path) = database_url.strip_prefix("sqlite:///") {
            return PathBuf::from(path);
        }
    }

    if is_test_env() {
        return test_db_path();
    }

    if let Some(root) = env::var_os("ASF_ROOT") {
        return PathBuf::from(root).join("asf_local.db");
    }

    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("asf_local.db")
}

fn is_test_env() -> bool {
    env::var("ASF_ENV")
        .map(|value| value.trim().eq_ignore_ascii_case("test"))
        .unwrap_or(false)
}

fn test_db_path() -> PathBuf {
    if let Some(path) = env::var_os("ASF_TEST_DB") {
        return PathBuf::from(path);
    }
    if let Some(root) = env::var_os("ASF_ROOT") {
        return PathBuf::from(root).join("asf_test.db");
    }
    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("asf_test.db")
}

pub fn utc_now() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3f")
        .to_string()
}

pub fn stable_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
        }
        Value::Array(values) => {
            let items = values.iter().map(stable_json).collect::<Vec<_>>().join(",");
            format!("[{items}]")
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            let items = keys
                .into_iter()
                .map(|key| {
                    let encoded_key =
                        serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string());
                    let value = stable_json(&values[key]);
                    format!("{encoded_key}:{value}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{items}}}")
        }
    }
}

pub fn sha256_text(value: &Value) -> String {
    let digest = Sha256::digest(stable_json(value).as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

pub fn redact_text(text: &str) -> String {
    let mut redacted = text.to_string();
    for pattern in secret_patterns() {
        redacted = pattern.replace_all(&redacted, "[REDACTED]").into_owned();
    }
    redacted
}

pub fn preview_value(value: &Value, max_bytes: usize) -> String {
    redact_text(&output_preview_text(value, max_bytes))
}

pub struct ClaudeTraceStore {
    db: DbPool,
}

pub struct HermesTraceStore {
    db: DbPool,
}

impl ClaudeTraceStore {
    pub fn open(db_path: &Path) -> Self {
        Self {
            db: open_trace_db(db_path, CLAUDE_SCHEMA),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        tool_name: &str,
        asf_tool_name: &str,
        args: &Value,
        output: Option<&Value>,
        verdict: &str,
        outcome: &str,
        reason: &str,
        confidence: Option<f64>,
        session_id: Option<&str>,
        trace_id: Option<&str>,
        audit_hash: Option<&str>,
        transcript_path: Option<&str>,
        tool_call_id: Option<&str>,
    ) -> Result<String, String> {
        let row_id = Uuid::new_v4().simple().to_string();
        let now = utc_now();
        let max_preview_bytes = max_preview_bytes(&["ASF_HOOK_MAX_PREVIEW_BYTES"], 8192);
        let args_hash = sha256_text(args);
        let args_preview = preview_value(args, max_preview_bytes);
        let output_hash = output.map(sha256_text);
        let output_preview = output.map(|value| preview_value(value, max_preview_bytes));
        let agent_id = namespaced_agent_id(DEFAULT_CLAUDE_AGENT_ID);
        let agent_model = env::var("ASF_CLAUDE_AGENT_MODEL")
            .unwrap_or_else(|_| DEFAULT_CLAUDE_AGENT_MODEL.to_string());

        let conn = self
            .db
            .lock()
            .map_err(|_| "trace store database mutex poisoned".to_string())?;
        conn.execute(
            r#"
            INSERT INTO claude_tool_traces (
                id, timestamp, source, agent_id, agent_model, session_id,
                transcript_path, tool_call_id, claude_tool_name, asf_tool_name,
                args_hash, args_preview, output_hash, output_preview, verdict,
                outcome, reason, confidence, trace_id, audit_hash, created_at
            ) VALUES (?1, ?2, 'claude-code', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                      ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
            "#,
            params![
                row_id,
                now,
                agent_id,
                agent_model,
                session_id,
                transcript_path,
                tool_call_id,
                tool_name,
                asf_tool_name,
                args_hash,
                args_preview,
                output_hash,
                output_preview,
                verdict,
                outcome,
                reason,
                confidence,
                trace_id,
                audit_hash,
                now,
            ],
        )
        .map_err(|err| err.to_string())?;

        Ok(row_id)
    }
}

impl HermesTraceStore {
    pub fn open(db_path: &Path) -> Self {
        Self {
            db: open_trace_db(db_path, HERMES_SCHEMA),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        tool_name: &str,
        asf_tool_name: &str,
        args: &Value,
        output: Option<&Value>,
        verdict: &str,
        outcome: &str,
        reason: &str,
        confidence: Option<f64>,
        session_id: Option<&str>,
        trace_id: Option<&str>,
        audit_hash: Option<&str>,
        agent_type: Option<&str>,
        task_id: Option<&str>,
    ) -> Result<String, String> {
        let row_id = Uuid::new_v4().simple().to_string();
        let now = utc_now();
        let max_preview_bytes = max_preview_bytes(
            &["ASF_HERMES_MAX_PREVIEW_BYTES", "ASF_HERMES_MAX_ARG_BYTES"],
            2048,
        );
        let args_hash = sha256_text(args);
        let args_preview = preview_value(args, max_preview_bytes);
        let output_hash = output.map(sha256_text);
        let output_preview = output.map(|value| preview_value(value, max_preview_bytes));
        let agent_id = env::var("ASF_HERMES_AGENT_ID")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_HERMES_AGENT_ID.to_string());
        let agent_model = env::var("ASF_HERMES_AGENT_MODEL").ok();
        let agent_type = agent_type.unwrap_or(DEFAULT_HERMES_AGENT_TYPE);

        let conn = self
            .db
            .lock()
            .map_err(|_| "trace store database mutex poisoned".to_string())?;
        conn.execute(
            r#"
            INSERT INTO hermes_tool_traces (
                id, timestamp, source, agent_id, agent_type, agent_model,
                session_id, task_id, tool_call_id, hermes_tool_name, asf_tool_name,
                args_hash, args_preview, output_hash, output_preview, verdict,
                outcome, reason, confidence, trace_id, audit_hash, created_at
            ) VALUES (?1, ?2, 'hermes', ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, ?10,
                      ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
            "#,
            params![
                row_id,
                now,
                agent_id,
                agent_type,
                agent_model,
                session_id,
                task_id,
                tool_name,
                asf_tool_name,
                args_hash,
                args_preview,
                output_hash,
                output_preview,
                verdict,
                outcome,
                reason,
                confidence,
                trace_id,
                audit_hash,
                now,
            ],
        )
        .map_err(|err| err.to_string())?;

        Ok(row_id)
    }
}

fn open_trace_db(db_path: &Path, schema: &str) -> DbPool {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).unwrap_or_else(|err| {
                panic!(
                    "failed to create SQLite database directory {}: {err}",
                    parent.display()
                )
            });
        }
    }

    let conn = Connection::open(db_path).unwrap_or_else(|err| {
        panic!(
            "failed to open SQLite database at {}: {err}",
            db_path.display()
        )
    });
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
        .unwrap_or_else(|err| panic!("failed to configure trace database: {err}"));
    conn.execute_batch(schema)
        .unwrap_or_else(|err| panic!("failed to initialize trace database schema: {err}"));
    DbPool::new(conn)
}

fn max_preview_bytes(env_names: &[&str], default: usize) -> usize {
    env_names
        .iter()
        .filter_map(|name| env::var(name).ok())
        .find_map(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn namespaced_agent_id(agent_id: &str) -> String {
    if is_test_env() && !agent_id.starts_with("test-") {
        format!("test-{agent_id}")
    } else {
        agent_id.to_string()
    }
}

fn secret_patterns() -> &'static [Regex] {
    static SECRET_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    SECRET_PATTERNS
        .get_or_init(|| {
            [
                r"-----BEGIN [A-Z ]* PRIVATE KEY-----",
                r#"(?i)\b(api[_-]?key|secret|token|password)\s*[=:]\s*[^\s'\"]{8,}"#,
                r"(?i)\b(bearer|sk-[a-z0-9_-]{12,}|ghp_[a-z0-9_]{20,})",
            ]
            .into_iter()
            .filter_map(|pattern| Regex::new(pattern).ok())
            .collect()
        })
        .as_slice()
}
