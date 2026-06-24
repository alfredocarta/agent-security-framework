use crate::registry::DbPool;
use rusqlite::{params, params_from_iter, types::Value as SqlValue, OptionalExtension};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Tamper-evident SQLite audit trail backed by a SHA-256 hash chain.
///
/// Schema note:
/// The original Python CREATE TABLE only contained:
///   hash, timestamp, agent_id, action, outcome, reason, human_reason, prev_hash, trace_id
/// The Rust port supports optional metadata/latency/confidence/session_id fields when those
/// columns exist. Add them with a migration such as:
///   ALTER TABLE audit_trail ADD COLUMN metadata TEXT;
///   ALTER TABLE audit_trail ADD COLUMN latency_ms INTEGER;
///   ALTER TABLE audit_trail ADD COLUMN confidence REAL;
///   ALTER TABLE audit_trail ADD COLUMN session_id TEXT;
/// `ensure_optional_columns` below can be called at DB open time to apply these SQLite
/// ALTER TABLE migrations idempotently. Even if that is not called, log_event detects the
/// live schema and silently omits optional columns that are absent.
pub struct AuditTrail {
    db: Arc<DbPool>,
    last_hash_by_agent: Arc<Mutex<HashMap<String, String>>>,
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub agent_id: String,
    pub action: String,
    pub outcome: String,
    pub reason: String,
    pub latency_ms: Option<i64>,
    pub confidence: Option<f64>,
    pub metadata: Option<JsonValue>,
    pub session_id: Option<String>,
    pub human_reason: Option<String>,
    pub trace_id: Option<String>,
}

impl AuditEvent {
    pub fn new(
        agent_id: impl Into<String>,
        action: impl Into<String>,
        outcome: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            action: action.into(),
            outcome: outcome.into(),
            reason: reason.into(),
            latency_ms: None,
            confidence: None,
            metadata: None,
            session_id: None,
            human_reason: None,
            trace_id: None,
        }
    }
}

impl AuditTrail {
    pub fn new(db: Arc<DbPool>) -> Self {
        Self {
            db,
            last_hash_by_agent: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_cache(
        db: Arc<DbPool>,
        last_hash_by_agent: Arc<Mutex<HashMap<String, String>>>,
    ) -> Self {
        Self {
            db,
            last_hash_by_agent,
        }
    }

    pub fn last_hash_for(&self, agent_id: &str) -> Option<String> {
        self.last_hash_by_agent
            .lock()
            .ok()
            .and_then(|cache| cache.get(agent_id).cloned())
    }

    /// Return the last `n` outcome strings for `agent_id`, newest first.
    /// This mirrors the Python method's fail-closed behavior: any lock/DB/schema error returns [];
    /// errors are never propagated to callers.
    pub fn recent_outcomes_for(&self, agent_id: &str, n: usize) -> Vec<String> {
        let Ok(conn) = self.db.lock() else {
            return Vec::new();
        };

        let limit = i64::try_from(n).unwrap_or(i64::MAX);
        let mut stmt = match conn.prepare(
            "SELECT outcome FROM audit_trail \
             WHERE agent_id = ?1 \
             ORDER BY timestamp DESC \
             LIMIT ?2",
        ) {
            Ok(stmt) => stmt,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map(params![agent_id, limit], |row| row.get::<_, String>(0)) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(Result::ok).collect()
    }

    /// Insert one audit event and update the in-memory per-agent last-hash cache.
    ///
    /// Important integrity invariant:
    /// The DbPool mutex is held for the complete read -> compute -> write cycle so no two
    /// threads sharing this pool can observe the same prev_hash and fork the hash chain.
    pub fn log_event(&self, event: AuditEvent) -> rusqlite::Result<String> {
        let conn = self.db.lock().map_err(|_| mutex_poisoned_error("DbPool"))?;

        // Keep a DB-level write lock as well. The process-local mutex preserves the invariant
        // for this DbPool; BEGIN IMMEDIATE also avoids inter-process writers racing this insert.
        conn.execute("BEGIN IMMEDIATE", [])?;

        let result = (|| -> rusqlite::Result<String> {
            let prev_hash = conn
                .query_row(
                    "SELECT hash FROM audit_trail ORDER BY timestamp DESC LIMIT 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .unwrap_or_else(|| ZERO_HASH.to_string());

            let hash = sha256_hex(format!(
                "{}{}{}{}{}",
                event.agent_id, event.action, event.outcome, event.reason, prev_hash
            ));

            let now = utc_now();
            let columns = audit_trail_columns(&conn)?;
            insert_audit_event(&conn, &columns, &event, &hash, &prev_hash, &now)?;

            Ok(hash)
        })();

        match result {
            Ok(hash) => {
                conn.execute("COMMIT", [])?;
                if let Ok(mut cache) = self.last_hash_by_agent.lock() {
                    cache.insert(event.agent_id, hash.clone());
                }
                eprintln!("[AUDIT] Event stored: {}", &hash[..12]);
                Ok(hash)
            }
            Err(err) => {
                let _ = conn.execute("ROLLBACK", []);
                eprintln!("[AUDIT] Write error: {err}");
                Err(err)
            }
        }
    }

    /// Optional open-time migration helper for the Rust daemon.
    ///
    /// Call this once after opening the SQLite connection if you want the optional Rust fields
    /// physically persisted. The ALTER TABLE errors are intentionally ignored because SQLite
    /// reports an error when a column already exists.
    pub fn ensure_optional_columns(&self) -> rusqlite::Result<()> {
        let conn = self.db.lock().map_err(|_| mutex_poisoned_error("DbPool"))?;
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
            ",
        )?;

        let _ = conn.execute("ALTER TABLE audit_trail ADD COLUMN metadata TEXT", []);
        let _ = conn.execute("ALTER TABLE audit_trail ADD COLUMN latency_ms INTEGER", []);
        let _ = conn.execute("ALTER TABLE audit_trail ADD COLUMN confidence REAL", []);
        let _ = conn.execute("ALTER TABLE audit_trail ADD COLUMN session_id TEXT", []);
        Ok(())
    }
}

fn insert_audit_event(
    conn: &rusqlite::Connection,
    existing_columns: &HashSet<String>,
    event: &AuditEvent,
    hash: &str,
    prev_hash: &str,
    timestamp: &str,
) -> rusqlite::Result<()> {
    let mut columns = Vec::<&str>::new();
    let mut values = Vec::<SqlValue>::new();

    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "hash",
        SqlValue::Text(hash.to_string()),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "timestamp",
        SqlValue::Text(timestamp.to_string()),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "agent_id",
        SqlValue::Text(event.agent_id.clone()),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "action",
        SqlValue::Text(event.action.clone()),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "outcome",
        SqlValue::Text(event.outcome.clone()),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "reason",
        SqlValue::Text(event.reason.clone()),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "human_reason",
        optional_text(&event.human_reason),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "prev_hash",
        SqlValue::Text(prev_hash.to_string()),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "trace_id",
        optional_text(&event.trace_id),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "latency_ms",
        event
            .latency_ms
            .map(SqlValue::Integer)
            .unwrap_or(SqlValue::Null),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "confidence",
        event
            .confidence
            .map(SqlValue::Real)
            .unwrap_or(SqlValue::Null),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "metadata",
        event
            .metadata
            .as_ref()
            .and_then(|value| serde_json::to_string(value).ok())
            .map(SqlValue::Text)
            .unwrap_or(SqlValue::Null),
    );
    push_column(
        &mut columns,
        &mut values,
        existing_columns,
        "session_id",
        optional_text(&event.session_id),
    );

    let placeholders = (1..=columns.len())
        .map(|idx| format!("?{idx}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO audit_trail ({}) VALUES ({})",
        columns.join(", "),
        placeholders
    );

    conn.execute(&sql, params_from_iter(values))?;
    Ok(())
}

fn push_column(
    columns: &mut Vec<&str>,
    values: &mut Vec<SqlValue>,
    existing_columns: &HashSet<String>,
    column: &'static str,
    value: SqlValue,
) {
    if existing_columns.contains(column) {
        columns.push(column);
        values.push(value);
    }
}

fn optional_text(value: &Option<String>) -> SqlValue {
    value
        .as_ref()
        .map(|value| SqlValue::Text(value.clone()))
        .unwrap_or(SqlValue::Null)
}

fn audit_trail_columns(conn: &rusqlite::Connection) -> rusqlite::Result<HashSet<String>> {
    let mut stmt = conn.prepare("PRAGMA table_info(audit_trail)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    rows.collect()
}

fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(input.as_ref());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

fn utc_now() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3f")
        .to_string()
}

fn mutex_poisoned_error(name: &str) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(format!("{name} mutex poisoned"))
}
