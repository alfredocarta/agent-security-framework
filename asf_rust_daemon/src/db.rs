use rusqlite::{params, Connection};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn namespaced_agent_id(agent_id: &str) -> String {
    if is_test_env() && !agent_id.starts_with("test-") {
        format!("test-{agent_id}")
    } else {
        agent_id.to_string()
    }
}

pub fn write_deny_record(
    db_path: &Path,
    req: &crate::protocol::CheckRequest,
    reason: &str,
    outcome: &str,
) -> rusqlite::Result<()> {
    let conn = Connection::open(db_path)?;
    prepare_conn(&conn)?;

    let trace_fields = build_trace_fields(req);

    conn.execute("BEGIN IMMEDIATE", [])?;

    let prev_hash: String = conn
        .query_row(
            "SELECT hash FROM audit_trail ORDER BY timestamp DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "0".repeat(64));

    let action = &req.tool_name;
    let audit_data = format!(
        "{}{}{}{}{}",
        trace_fields.agent_id, action, outcome, reason, prev_hash
    );
    let audit_hash = sha256_hex(audit_data.as_bytes());
    let now = utc_now();
    let username = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_default();
    let hostname = get_hostname();

    conn.execute(
        "
        INSERT INTO audit_trail
            (hash, timestamp, agent_id, action, outcome, reason, human_reason, prev_hash, trace_id, session_id, hostname, username)
        VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?10, ?11)
        ",
        params![
            audit_hash,
            now,
            trace_fields.agent_id.as_str(),
            action,
            outcome,
            reason,
            prev_hash,
            trace_fields.trace_id.as_str(),
            req.session_id,
            hostname,
            username,
        ],
    )?;

    insert_claude_trace(
        &conn,
        req,
        &trace_fields,
        "DENY",
        outcome,
        reason,
        Some(audit_hash.as_str()),
    )?;

    conn.execute("COMMIT", [])?;
    Ok(())
}

pub fn write_claude_trace(
    db_path: &Path,
    req: &crate::protocol::CheckRequest,
    verdict: &str,
    outcome: &str,
    reason: &str,
) -> rusqlite::Result<()> {
    let conn = Connection::open(db_path)?;
    prepare_conn(&conn)?;
    let trace_fields = build_trace_fields(req);
    insert_claude_trace(&conn, req, &trace_fields, verdict, outcome, reason, None)
}

struct TraceFields {
    agent_id: String,
    agent_model: String,
    args_hash: String,
    args_preview: String,
    tool_call_id: String,
    trace_id: String,
}

fn prepare_conn(conn: &Connection) -> rusqlite::Result<()> {
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
            trace_id TEXT,
            session_id TEXT,
            hostname TEXT,
            username TEXT
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
            confidence REAL,
            trace_id TEXT,
            audit_hash TEXT,
            created_at TEXT NOT NULL
        );
        ",
    )?;
    let _ = conn.execute("ALTER TABLE audit_trail ADD COLUMN hostname TEXT", []);
    let _ = conn.execute("ALTER TABLE audit_trail ADD COLUMN username TEXT", []);
    let _ = conn.execute("ALTER TABLE audit_trail ADD COLUMN session_id TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE claude_tool_traces ADD COLUMN confidence REAL",
        [],
    );
    Ok(())
}

fn build_trace_fields(req: &crate::protocol::CheckRequest) -> TraceFields {
    let stable_args = stable_json_value(&req.tool_input);
    let args_hash = sha256_hex(&stable_args);
    let tool_call_id = effective_tool_call_id(
        req.tool_use_id.as_deref(),
        req.session_id.as_deref(),
        req.transcript_path.as_deref(),
        &req.tool_name,
        &args_hash,
    );
    let trace_id = compute_trace_id(
        req.session_id.as_deref(),
        &tool_call_id,
        &req.tool_name,
        &args_hash,
    );
    let agent_model = env::var("ASF_CLAUDE_AGENT_MODEL")
        .unwrap_or_else(|_| "claude-sonnet-4-6 via Claude Code".to_string());

    TraceFields {
        agent_id: namespaced_agent_id(&req.agent_id),
        agent_model,
        args_hash,
        args_preview: truncate_utf8(&stable_args, 8192),
        tool_call_id,
        trace_id,
    }
}

fn insert_claude_trace(
    conn: &Connection,
    req: &crate::protocol::CheckRequest,
    trace_fields: &TraceFields,
    verdict: &str,
    outcome: &str,
    reason: &str,
    audit_hash: Option<&str>,
) -> rusqlite::Result<()> {
    let asf_tool = crate::forwarder::asf_tool_name(&req.tool_name);
    let now = utc_now();
    let row_id = uuid::Uuid::new_v4().simple().to_string();

    conn.execute(
        "
        INSERT INTO claude_tool_traces
            (id, timestamp, source, agent_id, agent_model, session_id, transcript_path,
             tool_call_id, claude_tool_name, asf_tool_name, args_hash, args_preview,
             output_hash, output_preview, verdict, outcome, reason, confidence, trace_id, audit_hash, created_at)
        SELECT
            ?1, ?2, 'claude-code', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
            NULL, NULL, ?12, ?13, ?14, NULL, ?15, ?16, ?17
        WHERE NOT EXISTS (
            SELECT 1 FROM claude_tool_traces WHERE tool_call_id = ?7
        )
        ",
        params![
            row_id,
            now,
            trace_fields.agent_id.as_str(),
            trace_fields.agent_model.as_str(),
            req.session_id,
            req.transcript_path,
            trace_fields.tool_call_id.as_str(),
            req.tool_name,
            asf_tool,
            trace_fields.args_hash.as_str(),
            trace_fields.args_preview.as_str(),
            verdict,
            outcome,
            reason,
            trace_fields.trace_id.as_str(),
            audit_hash,
            now,
        ],
    )?;
    Ok(())
}

fn get_hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
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
        Value::Number(_) | Value::String(_) => {
            serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
        }
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
                    let encoded_key =
                        serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string());
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
    compute_tool_call_id_from_parts(
        session_id.as_deref(),
        transcript_path.as_deref(),
        tool_name,
        args_hash,
    )
}

pub fn effective_tool_call_id(
    explicit_tool_call_id: Option<&str>,
    session_id: Option<&str>,
    transcript_path: Option<&str>,
    tool_name: &str,
    args_hash: &str,
) -> String {
    explicit_tool_call_id
        .map(str::to_string)
        .unwrap_or_else(|| {
            compute_tool_call_id_from_parts(session_id, transcript_path, tool_name, args_hash)
        })
}

fn compute_tool_call_id_from_parts(
    session_id: Option<&str>,
    transcript_path: Option<&str>,
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
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    seed.insert(
        "tool_name".to_string(),
        Value::String(tool_name.to_string()),
    );
    seed.insert(
        "transcript_path".to_string(),
        transcript_path
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );

    let seed = stable_json_value(&Value::Object(seed));
    format!("claude-call-{}", &sha256_hex(seed.as_bytes())[..16])
}

pub fn compute_trace_id(
    session_id: Option<&str>,
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
            .map(|value| Value::String(value.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CheckRequest;
    use rusqlite::Connection;
    use serde_json::json;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_db_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "asf-rust-daemon-allow-trace-{}-{nanos}.db",
            std::process::id()
        ))
    }

    #[test]
    fn fast_path_allow_trace_matches_post_tool_use_finish_trace() {
        let db_path = unique_test_db_path();
        let tool_input = json!({"command": "pwd"});
        let req = CheckRequest {
            tool_name: "Bash".to_string(),
            tool_input,
            session_id: Some("session-fast-allow".to_string()),
            transcript_path: Some("/tmp/transcript-fast-allow.jsonl".to_string()),
            tool_use_id: None,
            agent_id: "claude-code-agent".to_string(),
        };
        let args_hash = compute_args_hash(&req.tool_input);
        let expected_tool_call_id = compute_tool_call_id(
            &req.session_id,
            &req.transcript_path,
            &req.tool_name,
            &args_hash,
        );

        write_claude_trace(
            &db_path,
            &req,
            "ALLOW",
            "HEURISTIC_CLEAR",
            "Cleared by heuristic (0%)",
        )
        .expect("write fast-path allow trace");
        write_claude_trace(
            &db_path,
            &req,
            "ALLOW",
            "HEURISTIC_CLEAR",
            "Cleared by heuristic (0%)",
        )
        .expect("idempotent fast-path allow trace");

        let conn = Connection::open(&db_path).expect("open test db");
        let trace_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM claude_tool_traces WHERE tool_call_id = ?1",
                [expected_tool_call_id.as_str()],
                |row| row.get(0),
            )
            .expect("count trace rows");
        assert_eq!(trace_count, 1);

        let (tool_call_id, args_preview, agent_id, claude_tool_name, asf_tool_name, verdict): (
            String,
            String,
            String,
            String,
            String,
            String,
        ) = conn
            .query_row(
                "SELECT tool_call_id, args_preview, agent_id, claude_tool_name, asf_tool_name, verdict \
                 FROM claude_tool_traces WHERE tool_call_id = ?1",
                [expected_tool_call_id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("read allow trace row");

        assert_eq!(tool_call_id, expected_tool_call_id);
        assert_eq!(args_preview, stable_json_value(&req.tool_input));
        assert_eq!(agent_id, "claude-code-agent");
        assert_eq!(claude_tool_name, "Bash");
        assert_eq!(asf_tool_name, "shell");
        assert_eq!(verdict, "ALLOW");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let project_root = manifest_dir
            .parent()
            .expect("manifest has project parent")
            .to_path_buf();
        let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_string());
        let finish = Command::new(python)
            .current_dir(&project_root)
            .arg("-c")
            .arg(
                r#"
import sys
from claude_trace_store import ClaudeTraceStore, make_tool_call_id
payload = {
    "session_id": "session-fast-allow",
    "transcript_path": "/tmp/transcript-fast-allow.jsonl",
}
assert make_tool_call_id(payload, "Bash", {"command": "pwd"}) == sys.argv[2]
updated = ClaudeTraceStore(sys.argv[1]).finish_trace(
    result={"content": "fast-path output recorded"},
    tool_call_id=sys.argv[2],
    session_id="session-fast-allow",
)
assert updated == 1, updated
"#,
            )
            .arg(&db_path)
            .arg(&expected_tool_call_id)
            .output()
            .expect("run Python finish_trace");
        assert!(
            finish.status.success(),
            "finish_trace failed\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&finish.stdout),
            String::from_utf8_lossy(&finish.stderr)
        );

        let output_preview: String = conn
            .query_row(
                "SELECT output_preview FROM claude_tool_traces WHERE tool_call_id = ?1",
                [expected_tool_call_id.as_str()],
                |row| row.get(0),
            )
            .expect("read output preview");
        assert!(output_preview.contains("fast-path output recorded"));

        drop(conn);
        let _ = std::fs::remove_file(db_path);
    }
}
