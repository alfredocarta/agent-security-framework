use rusqlite::{params, Connection};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write;
use std::path::{Path, PathBuf};

pub fn resolve_db_path() -> PathBuf {
    if let Some(path) = env::var_os("ASF_HOOK_DB") {
        return PathBuf::from(path);
    }

    if let Ok(database_url) = env::var("DATABASE_URL") {
        if let Some(path) = database_url.strip_prefix("sqlite:///") {
            return PathBuf::from(path);
        }
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

pub fn write_deny_record(
    db_path: &Path,
    req: &crate::protocol::CheckRequest,
    reason: &str,
    outcome: &str,
) -> rusqlite::Result<()> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS audit_trail (
            hash TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            agent_id TEXT,
            action TEXT,
            outcome TEXT,
            reason TEXT,
            human_reason TEXT,
            prev_hash TEXT,
            trace_id TEXT
        );

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
            trace_id TEXT,
            audit_hash TEXT,
            created_at TEXT NOT NULL
        );
        ",
    )?;

    let stable_args = stable_json_value(&req.tool_input);
    let args_hash = sha256_hex(&stable_args);
    let tool_call_id = compute_tool_call_id(
        &req.session_id,
        &req.transcript_path,
        &req.tool_name,
        &args_hash,
    );
    let trace_id = compute_trace_id(&req.session_id, &tool_call_id, &req.tool_name, &args_hash);
    let asf_tool = crate::forwarder::asf_tool_name(&req.tool_name);

    conn.execute("BEGIN IMMEDIATE", [])?;

    let prev_hash: String = conn
        .query_row(
            "SELECT hash FROM audit_trail ORDER BY timestamp DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "0".repeat(64));

    let agent_id = "claude-code-agent";
    let action = &req.tool_name;
    let audit_data = format!("{}{}{}{}{}", agent_id, action, outcome, reason, prev_hash);
    let audit_hash = sha256_hex(audit_data.as_bytes());
    let now = utc_now();
    let row_id = uuid::Uuid::new_v4().simple().to_string();
    let args_preview = truncate_utf8(&stable_args, 8192);
    let agent_model = env::var("ASF_CLAUDE_AGENT_MODEL")
        .unwrap_or_else(|_| "claude-sonnet-4-6 via Claude Code".to_string());

    conn.execute(
        "
        INSERT INTO audit_trail
            (hash, timestamp, agent_id, action, outcome, reason, human_reason, prev_hash, trace_id)
        VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8)
        ",
        params![audit_hash, now, agent_id, action, outcome, reason, prev_hash, trace_id,],
    )?;

    conn.execute(
        "
        INSERT INTO claude_tool_traces
            (id, timestamp, source, agent_id, agent_model, session_id, transcript_path,
             tool_call_id, claude_tool_name, asf_tool_name, args_hash, args_preview,
             output_hash, output_preview, verdict, outcome, reason, trace_id, audit_hash, created_at)
        VALUES
            (?1, ?2, 'claude-code', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
             NULL, NULL, 'DENY', ?12, ?13, ?14, ?15, ?16)
        ",
        params![
            row_id,
            now,
            agent_id,
            agent_model,
            req.session_id,
            req.transcript_path,
            tool_call_id,
            req.tool_name,
            asf_tool,
            args_hash,
            args_preview,
            outcome,
            reason,
            trace_id,
            audit_hash,
            now,
        ],
    )?;

    conn.execute("COMMIT", [])?;
    Ok(())
}

fn utc_now() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3f")
        .to_string()
}

pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(input.as_ref());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

fn stable_json_value(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(_) | Value::String(_) => serde_json::to_string(v).unwrap(),
        Value::Array(values) => {
            let items = values
                .iter()
                .map(stable_json_value)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{items}]")
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            let items = keys
                .into_iter()
                .map(|key| {
                    let encoded_key = serde_json::to_string(key).unwrap();
                    let value = stable_json_value(&values[key]);
                    format!("{encoded_key}: {value}")
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{items}}}")
        }
    }
}

pub fn compute_args_hash(tool_input: &serde_json::Value) -> String {
    sha256_hex(stable_json_value(tool_input))
}

pub fn compute_tool_call_id(
    session_id: &Option<String>,
    transcript_path: &Option<String>,
    tool_name: &str,
    args_hash: &str,
) -> String {
    let mut seed = Map::new();
    seed.insert(
        "args_hash".to_string(),
        Value::String(args_hash.to_string()),
    );
    seed.insert(
        "session_id".to_string(),
        session_id
            .as_ref()
            .map(|value| Value::String(value.clone()))
            .unwrap_or(Value::Null),
    );
    seed.insert(
        "tool_name".to_string(),
        Value::String(tool_name.to_string()),
    );
    seed.insert(
        "transcript_path".to_string(),
        transcript_path
            .as_ref()
            .map(|value| Value::String(value.clone()))
            .unwrap_or(Value::Null),
    );

    let seed = stable_json_value(&Value::Object(seed));
    format!("claude-call-{}", &sha256_hex(seed.as_bytes())[..16])
}

fn compute_trace_id(
    session_id: &Option<String>,
    tool_call_id: &str,
    tool_name: &str,
    args_hash: &str,
) -> String {
    let mut seed = Map::new();
    seed.insert(
        "args_hash".to_string(),
        Value::String(args_hash.to_string()),
    );
    seed.insert(
        "session_id".to_string(),
        session_id
            .as_ref()
            .map(|value| Value::String(value.clone()))
            .unwrap_or(Value::Null),
    );
    seed.insert(
        "tool_call_id".to_string(),
        Value::String(tool_call_id.to_string()),
    );
    seed.insert(
        "tool_name".to_string(),
        Value::String(tool_name.to_string()),
    );

    let seed = stable_json_value(&Value::Object(seed));
    format!("claude-{}", &sha256_hex(seed.as_bytes())[..16])
}

fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }

    let mut boundary = max_bytes;
    while !s.is_char_boundary(boundary) {
        boundary -= 1;
    }

    let truncated_bytes = s.len() - boundary;
    format!("{}...[truncated {truncated_bytes} bytes]", &s[..boundary])
}
