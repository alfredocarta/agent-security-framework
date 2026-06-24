use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::path::Path;
use std::sync::Mutex;

pub type DbPool = std::sync::Mutex<rusqlite::Connection>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentModel {
    pub agent_id: String,
    pub risk_level: Option<String>,
    pub permissions: Value,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditModel {
    pub hash: String,
    pub timestamp: Option<String>,
    pub agent_id: Option<String>,
    pub action: Option<String>,
    pub outcome: Option<String>,
    pub reason: Option<String>,
    pub human_reason: Option<String>,
    pub prev_hash: Option<String>,
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoliciesModel {
    pub key: String,
    pub value: Value,
    pub content_hash: Option<String>,
}

pub fn open_db(path: &Path) -> DbPool {
    let conn = Connection::open(path).unwrap_or_else(|err| {
        panic!(
            "failed to open SQLite database at {}: {err}",
            path.display()
        )
    });

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS agents (
            agent_id VARCHAR NOT NULL,
            risk_level VARCHAR,
            permissions TEXT,
            status VARCHAR,
            PRIMARY KEY (agent_id)
        );

        CREATE INDEX IF NOT EXISTS ix_agents_agent_id ON agents (agent_id);

        CREATE TABLE IF NOT EXISTS audit_trail (
            hash VARCHAR NOT NULL,
            timestamp DATETIME,
            agent_id VARCHAR,
            action VARCHAR,
            outcome VARCHAR,
            reason VARCHAR,
            human_reason VARCHAR,
            prev_hash VARCHAR,
            trace_id VARCHAR,
            PRIMARY KEY (hash)
        );

        CREATE TABLE IF NOT EXISTS policies (
            key VARCHAR NOT NULL,
            value TEXT,
            content_hash TEXT,
            PRIMARY KEY (key)
        );
        ",
    )
    .unwrap_or_else(|err| panic!("failed to initialize registry database schema: {err}"));

    // Python registry.py runs this migration at startup and ignores duplicate-column
    // failures. Keep the same behavior so older audit_trail tables are upgraded.
    let _ = conn.execute("ALTER TABLE audit_trail ADD COLUMN trace_id TEXT", []);

    Mutex::new(conn)
}

pub fn get_agent_permissions(db: &DbPool, agent_id: &str) -> rusqlite::Result<Value> {
    let conn = db.lock().expect("registry database mutex poisoned");
    let row = conn
        .query_row(
            "SELECT permissions, status FROM agents WHERE agent_id = ?1 LIMIT 1",
            params![agent_id],
            |row| {
                let permissions_json: Option<String> = row.get(0)?;
                let status: Option<String> = row.get(1)?;
                Ok((permissions_json, status))
            },
        )
        .optional()?;

    match row {
        Some((_permissions, Some(status))) if status == "suspended" => Ok(Value::Array(Vec::new())),
        Some((Some(permissions), _status)) => Ok(parse_json_or_null(&permissions)),
        Some((None, _)) | None => Ok(Value::Array(Vec::new())),
    }
}

pub fn suspend_agent(db: &DbPool, agent_id: &str) -> rusqlite::Result<()> {
    let conn = db.lock().expect("registry database mutex poisoned");
    conn.execute(
        "UPDATE agents SET status = 'suspended' WHERE agent_id = ?1",
        params![agent_id],
    )?;
    Ok(())
}

pub fn add_or_update_agent(
    db: &DbPool,
    agent_id: &str,
    risk_level: &str,
    permissions: &Value,
) -> rusqlite::Result<()> {
    let conn = db.lock().expect("registry database mutex poisoned");
    let permissions_json = serde_json::to_string(permissions)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;

    conn.execute(
        "
        INSERT INTO agents (agent_id, risk_level, permissions, status)
        VALUES (?1, ?2, ?3, 'active')
        ON CONFLICT(agent_id) DO UPDATE SET
            risk_level = excluded.risk_level,
            permissions = excluded.permissions,
            status = excluded.status
        ",
        params![agent_id, risk_level, permissions_json],
    )?;
    Ok(())
}

pub fn store_detection_patterns(db: &DbPool, patterns: &Value) -> rusqlite::Result<String> {
    let stable_json = stable_json_value(patterns);
    let content_hash = sha256_hex(stable_json.as_bytes());
    let value_json = serde_json::to_string(patterns)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;

    let conn = db.lock().expect("registry database mutex poisoned");
    conn.execute(
        "
        INSERT INTO policies (key, value, content_hash)
        VALUES ('detection_patterns', ?1, ?2)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            content_hash = excluded.content_hash
        ",
        params![value_json, content_hash],
    )?;

    Ok(content_hash)
}

pub fn get_detection_patterns(db: &DbPool) -> rusqlite::Result<Option<Value>> {
    let conn = db.lock().expect("registry database mutex poisoned");
    let value_json: Option<String> = conn
        .query_row(
            "SELECT value FROM policies WHERE key = 'detection_patterns' LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;

    Ok(value_json.map(|value| parse_json_or_null(&value)))
}

pub fn reinstate_agent(db: &DbPool, agent_id: &str) -> rusqlite::Result<()> {
    let conn = db.lock().expect("registry database mutex poisoned");
    conn.execute(
        "UPDATE agents SET status = 'active' WHERE agent_id = ?1 AND status = 'suspended'",
        params![agent_id],
    )?;
    Ok(())
}

pub fn agent_exists(db: &DbPool, agent_id: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().expect("registry database mutex poisoned");
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1 LIMIT 1)",
        params![agent_id],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

fn parse_json_or_null(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
}

fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(input.as_ref());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

// Mirrors Python's json.dumps(value, sort_keys=True) for the policy shapes used
// by ASF: sorted object keys and Python's default ", " / ": " separators.
fn stable_json_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn crud_round_trip() {
        let db = open_db(Path::new(":memory:"));
        let permissions = json!(["read_db", "communication"]);

        add_or_update_agent(&db, "billing_agent", "high", &permissions).unwrap();
        assert!(agent_exists(&db, "billing_agent").unwrap());
        assert_eq!(
            get_agent_permissions(&db, "billing_agent").unwrap(),
            permissions
        );

        suspend_agent(&db, "billing_agent").unwrap();
        assert_eq!(
            get_agent_permissions(&db, "billing_agent").unwrap(),
            json!([])
        );

        reinstate_agent(&db, "billing_agent").unwrap();
        assert_eq!(
            get_agent_permissions(&db, "billing_agent").unwrap(),
            permissions
        );
    }

    #[test]
    fn detection_patterns_round_trip_and_hash_is_stable() {
        let db = open_db(Path::new(":memory:"));
        let patterns = json!({"b": [2, 1], "a": true});

        let hash = store_detection_patterns(&db, &patterns).unwrap();
        assert_eq!(hash, sha256_hex(b"{\"a\": true, \"b\": [2, 1]}"));
        assert_eq!(get_detection_patterns(&db).unwrap(), Some(patterns));
    }
}
