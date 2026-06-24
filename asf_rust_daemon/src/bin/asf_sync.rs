//! Lightweight ASF -> ASE dashboard synchronizer.
//!
//! Operational note: `asf-sync` is intended to be launched independently before
//! starting Claude Code/Hermes. On Unix it also attempts `setsid(2)` on startup so
//! that, when it is spawned by another process, it does not share that process
//! group. If another launcher is used, spawn it with `std::process::Command` and
//! a `pre_exec` hook that calls `libc::setsid()`.

use reqwest::blocking::Client;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, Row};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

const DEFAULT_ENDPOINT: &str = "http://localhost:8000/api/events/ingest";
const DEFAULT_INTERVAL_SECS: u64 = 10;
const MAX_POST_ATTEMPTS: usize = 3;

// Keep these names aligned with registry.py::AuditModel.
const AUDIT_MODEL_FIELDS: &[&str] = &[
    "hash",
    "timestamp",
    "agent_id",
    "action",
    "outcome",
    "reason",
    "human_reason",
    "prev_hash",
    "trace_id",
];

#[derive(Debug)]
struct Config {
    db_path: PathBuf,
    state_path: PathBuf,
    endpoint: String,
    interval: Duration,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CursorState {
    last_cursor: i64,
}

#[derive(Debug)]
struct AuditBatch {
    events: Vec<Value>,
    max_cursor: i64,
}

fn main() {
    install_signal_handlers();
    detach_from_agent_process_group();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("asf-sync: configuration error: {err}");
            process::exit(2);
        }
    };

    if let Err(err) = run(config) {
        eprintln!("asf-sync: fatal error: {err}");
        process::exit(1);
    }
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let db_path = env::var_os("ASF_DB_PATH")
            .map(PathBuf::from)
            .unwrap_or(home_dir()?.join(".asf").join("asf_local.db"));
        let state_path = home_dir()?
            .join(".cache")
            .join("asf-hook")
            .join("sync_cursor.json");
        let endpoint =
            env::var("ASF_SYNC_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
        let interval_secs = env::var("ASF_SYNC_INTERVAL")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
            .unwrap_or(DEFAULT_INTERVAL_SECS);

        Ok(Self {
            db_path,
            state_path,
            endpoint,
            interval: Duration::from_secs(interval_secs),
        })
    }
}

fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
    let mut state = load_cursor(&config.state_path)?;

    eprintln!(
        "asf-sync: started db={} endpoint={} interval={}s cursor={}",
        config.db_path.display(),
        config.endpoint,
        config.interval.as_secs(),
        state.last_cursor
    );

    while !SHUTDOWN.load(Ordering::SeqCst) {
        if let Err(err) = sync_once(&config, &client, &mut state) {
            eprintln!("asf-sync: sync failed: {err}");
        }
        wait_or_shutdown(config.interval);
    }

    eprintln!("asf-sync: shutdown requested; flushing pending audit events");
    if let Err(err) = sync_once(&config, &client, &mut state) {
        eprintln!("asf-sync: final flush failed: {err}");
    }
    eprintln!("asf-sync: stopped at cursor={}", state.last_cursor);
    Ok(())
}

fn sync_once(
    config: &Config,
    client: &Client,
    state: &mut CursorState,
) -> Result<(), Box<dyn Error>> {
    let batch = read_new_audit_rows(&config.db_path, state.last_cursor)?;
    if batch.events.is_empty() {
        return Ok(());
    }

    post_events_with_retry(client, &config.endpoint, &batch.events)?;
    state.last_cursor = batch.max_cursor;
    save_cursor(&config.state_path, state)?;
    eprintln!(
        "asf-sync: synced {} event(s), cursor={}",
        batch.events.len(),
        state.last_cursor
    );
    Ok(())
}

fn read_new_audit_rows(db_path: &Path, last_cursor: i64) -> Result<AuditBatch, Box<dyn Error>> {
    let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.pragma_update(None, "busy_timeout", 5000)?;

    let columns = audit_trail_columns(&conn)?;
    let mut select_parts = vec!["rowid AS __cursor".to_string()];
    for field in AUDIT_MODEL_FIELDS {
        if columns.contains(*field) {
            select_parts.push(format!("\"{field}\""));
        }
    }

    let sql = format!(
        "SELECT {} FROM audit_trail WHERE rowid > ?1 ORDER BY rowid ASC",
        select_parts.join(", ")
    );
    let selected_fields: Vec<&str> = AUDIT_MODEL_FIELDS
        .iter()
        .copied()
        .filter(|field| columns.contains(*field))
        .collect();

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([last_cursor])?;
    let mut events = Vec::new();
    let mut max_cursor = last_cursor;

    while let Some(row) = rows.next()? {
        let cursor: i64 = row.get(0)?;
        max_cursor = max_cursor.max(cursor);
        events.push(row_to_audit_json(row, &selected_fields)?);
    }

    Ok(AuditBatch { events, max_cursor })
}

fn audit_trail_columns(conn: &Connection) -> Result<HashSet<String>, Box<dyn Error>> {
    let mut stmt = conn.prepare("PRAGMA table_info(audit_trail)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut columns = HashSet::new();
    for col in rows {
        columns.insert(col?);
    }
    if columns.is_empty() {
        return Err("audit_trail table does not exist or has no columns".into());
    }
    Ok(columns)
}

fn row_to_audit_json(row: &Row<'_>, selected_fields: &[&str]) -> Result<Value, Box<dyn Error>> {
    let mut event = Map::new();

    for field in AUDIT_MODEL_FIELDS {
        event.insert((*field).to_string(), Value::Null);
    }

    for (idx, field) in selected_fields.iter().enumerate() {
        let value = sqlite_value_to_json(row.get_ref(idx + 1)?);
        event.insert((*field).to_string(), value);
    }

    Ok(Value::Object(event))
}

fn sqlite_value_to_json(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(bytes) => String::from_utf8_lossy(bytes).into_owned().into(),
        ValueRef::Blob(bytes) => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .encode(bytes)
                .into()
        }
    }
}

fn post_events_with_retry(
    client: &Client,
    endpoint: &str,
    events: &[Value],
) -> Result<(), Box<dyn Error>> {
    let payload = json!({ "events": events });
    let mut backoff = Duration::from_secs(1);
    let mut last_error = String::new();

    for attempt in 1..=MAX_POST_ATTEMPTS {
        match client.post(endpoint).json(&payload).send() {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                let status = response.status();
                let body = response.text().unwrap_or_default();
                last_error = format!("HTTP {status}: {body}");
            }
            Err(err) => {
                last_error = err.to_string();
            }
        }

        if attempt < MAX_POST_ATTEMPTS {
            eprintln!(
                "asf-sync: POST attempt {attempt}/{MAX_POST_ATTEMPTS} failed: {last_error}; retrying in {}s",
                backoff.as_secs()
            );
            wait_or_shutdown(backoff);
            backoff *= 2;
        }
    }

    Err(format!("POST failed after {MAX_POST_ATTEMPTS} attempts: {last_error}").into())
}

fn load_cursor(path: &Path) -> Result<CursorState, Box<dyn Error>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(serde_json::from_str(&content)?),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(CursorState::default()),
        Err(err) => Err(Box::new(err)),
    }
}

fn save_cursor(path: &Path, state: &CursorState) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let content = serde_json::to_vec_pretty(state)?;
    fs::write(&tmp_path, content)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn home_dir() -> Result<PathBuf, Box<dyn Error>> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".into())
}

fn wait_or_shutdown(duration: Duration) {
    let deadline = std::time::Instant::now() + duration;
    while !SHUTDOWN.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(200)));
    }
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        );
    }
}

extern "C" fn handle_signal(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn detach_from_agent_process_group() {
    #[cfg(unix)]
    unsafe {
        if libc::setsid() == -1 {
            let err = io::Error::last_os_error();
            // EPERM is expected when the process is already a process-group leader.
            if err.raw_os_error() != Some(libc::EPERM) {
                eprintln!("asf-sync: warning: setsid failed: {err}");
            }
        }
    }
}
