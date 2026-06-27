use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;

const SCHEMA: i64 = 1;
const MAX_INPUT_CHARS: usize = 2000;

pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

pub fn input_id_value(value: &Value) -> String {
    let text = canonical_json(value);
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn input_id(input: &str) -> String {
    input_id_value(&Value::String(input.to_string()))
}

fn redact_text(input: &str) -> String {
    let mut out = input.to_string();
    let patterns = [
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r#"(?i)\b(api[_-]?key|secret|token|password)\s*[=:]\s*[^\s'\"]{8,}"#,
        r"(?i)\b(bearer)\s+[a-z0-9._~+/=-]{8,}",
        r"(?i)\bsk-[a-z0-9._-]{8,}",
        r"(?i)\bghp_[a-z0-9_]{20,}",
        r"\bAKIA[0-9A-Z]{16}\b",
    ];
    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            out = re.replace_all(&out, "[REDACTED_SECRET]").to_string();
        }
    }
    for name in ["ASF_HOOK_CANARY", "ASF_HERMES_CANARY"] {
        if let Ok(canary) = std::env::var(name) {
            if !canary.is_empty() {
                out = out.replace(&canary, "[REDACTED_CANARY]");
            }
        }
    }
    out
}

fn redact_value(value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact_text(&s)),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_value).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k, redact_value(v));
            }
            Value::Object(out)
        }
        other => other,
    }
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    input.chars().take(max_chars).collect()
}

fn norm(value: Value) -> Value {
    match value {
        Value::String(s) => match s.to_ascii_uppercase().as_str() {
            "ALLOW" | "DENY" | "UNCERTAIN" | "HITL" | "SAFE" | "DANGEROUS" | "UNAVAILABLE" => {
                Value::String(s.to_ascii_uppercase())
            }
            _ => Value::String(s),
        },
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                let rounded = (f * 10000.0).round() / 10000.0;
                serde_json::Number::from_f64(rounded)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            } else {
                Value::Number(n)
            }
        }
        Value::Array(values) => Value::Array(values.into_iter().map(norm).collect()),
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                if let Some(v) = map.get(&k) {
                    out.insert(k, norm(v.clone()));
                }
            }
            Value::Object(out)
        }
        other => other,
    }
}

fn write_record(
    op: &str,
    impl_name: &str,
    input_for_id: &Value,
    input_preview: String,
    out: Value,
) {
    let Ok(path) = std::env::var("ASF_CANONICAL_LOG") else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let mut rec = Map::new();
    rec.insert("op".to_string(), Value::String(op.to_string()));
    rec.insert("impl".to_string(), Value::String(impl_name.to_string()));
    rec.insert(
        "input_id".to_string(),
        Value::String(input_id_value(input_for_id)),
    );
    rec.insert(
        "input".to_string(),
        Value::String(truncate_chars(&redact_text(&input_preview), MAX_INPUT_CHARS)),
    );
    rec.insert("out".to_string(), norm(redact_value(out)));
    rec.insert("schema".to_string(), Value::Number(SCHEMA.into()));
    if let Ok(mut fh) = OpenOptions::new().create(true).append(true).open(path) {
        if let Ok(line) = serde_json::to_string(&Value::Object(rec)) {
            let _ = writeln!(fh, "{line}");
        }
    }
}

pub fn log(op: &str, impl_name: &str, input: &str, out: Value) {
    write_record(
        op,
        impl_name,
        &Value::String(input.to_string()),
        input.to_string(),
        out,
    );
}

pub fn log_value(op: &str, impl_name: &str, input: &Value, out: Value) {
    write_record(op, impl_name, input, canonical_json(input), out);
}
