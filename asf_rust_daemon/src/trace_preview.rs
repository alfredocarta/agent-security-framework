use crate::canonical_log;
use serde_json::{json, Map, Value};

const CONTENT_KEYS: &[&str] = &[
    "output", "stdout", "content", "text", "result", "message", "body",
];
const NOISE_KEYS: &[&str] = &[
    "originalfile",
    "filepath",
    "file_path",
    "path",
    "type",
    "numlines",
    "totallines",
    "startline",
    "offset",
    "limit",
    "interrupted",
    "isimage",
    "nooutputexpected",
    "sandboxed",
    "sandbox_warning",
    "mode",
    "gitoperation",
    "durationms",
    "duration_ms",
    "returncode",
    "exit_code",
    "stderr",
];

pub fn output_preview_text(value: &Value, max_bytes: usize) -> String {
    let unwrapped = unwrap_json_string(value, 3);
    let mut text = extract_envelope_text(&unwrapped, 0);

    if let Value::Object(map) = &unwrapped {
        if let Some(stderr) = map.get("stderr") {
            let stderr_text = value_to_plain_string(stderr);
            if !stderr_text.is_empty() {
                text = format!("{text}\nstderr: {stderr_text}");
            }
        }
        if let Some(exit_code) = map.get("exit_code") {
            if is_non_zero_exit(exit_code) {
                text = format!("{text}\nexit_code: {}", value_to_plain_string(exit_code));
            }
        }
    }

    let preview = truncate_preview_text(&text, max_bytes);
    canonical_log::log_value(
        "trace_output_preview",
        "rust",
        value,
        json!({"preview": preview}),
    );
    preview
}

pub fn truncate_preview_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut boundary = max_bytes.min(text.len());
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let truncated_bytes = text.len().saturating_sub(boundary);
    format!("{}…[truncated {truncated_bytes} bytes]", &text[..boundary])
}

fn unwrap_json_string(value: &Value, max_depth: usize) -> Value {
    let mut current = value.clone();
    for _ in 0..max_depth {
        let Value::String(text) = &current else {
            break;
        };
        if !looks_like_json_string(text) {
            break;
        }
        match serde_json::from_str::<Value>(text) {
            Ok(parsed) => {
                let was_string = matches!(parsed, Value::String(_));
                current = parsed;
                if !was_string {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    current
}

fn looks_like_json_string(value: &str) -> bool {
    matches!(
        value.trim_start().chars().next(),
        Some('{') | Some('[') | Some('"')
    )
}

fn extract_envelope_text(value: &Value, depth: usize) -> String {
    let unwrapped = unwrap_json_string(value, 3);
    match &unwrapped {
        Value::String(text) => text.clone(),
        Value::Array(values) => {
            if !values.is_empty() && values.iter().all(Value::is_string) {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                pretty_json(&unwrapped)
            }
        }
        Value::Object(map) => extract_object_text(map, depth),
        _ => pretty_json(&unwrapped),
    }
}

fn extract_object_text(map: &Map<String, Value>, depth: usize) -> String {
    for key in CONTENT_KEYS {
        if let Some(Value::String(text)) = map.get(*key) {
            return text.clone();
        }
    }

    if depth < 2 {
        for nested in map.values() {
            if matches!(nested, Value::Object(_)) {
                let inner = extract_envelope_text(nested, depth + 1);
                let trimmed = inner.trim_start();
                if !inner.is_empty() && !trimmed.starts_with('{') && !trimmed.starts_with('[') {
                    return inner;
                }
            }
        }
    }

    for (key, value) in map {
        if !is_noise_key(key)
            && matches!(value, Value::Array(values) if !values.is_empty() && values.iter().all(Value::is_string))
        {
            if let Value::Array(values) = value {
                return values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n");
            }
        }
    }

    let labeled = map
        .iter()
        .filter_map(|(key, value)| match value {
            Value::String(text) if !text.trim().is_empty() && !is_noise_key(key) => {
                Some((key.as_str(), text.as_str()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    if labeled.len() == 1 {
        return labeled[0].1.to_string();
    }
    if !labeled.is_empty() {
        return labeled
            .into_iter()
            .map(|(key, value)| format!("{key}:\n{value}"))
            .collect::<Vec<_>>()
            .join("\n\n");
    }

    let denoised = map
        .iter()
        .filter(|(key, _)| !is_noise_key(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();

    if denoised.is_empty() {
        pretty_json(&Value::Object(map.clone()))
    } else {
        pretty_json(&Value::Object(denoised))
    }
}

fn is_noise_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    NOISE_KEYS.contains(&lower.as_str())
}

fn is_non_zero_exit(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Number(number) => number.as_i64().map(|n| n != 0).unwrap_or(true),
        Value::String(text) => {
            if text.is_empty() {
                false
            } else {
                text.parse::<i64>().map(|n| n != 0).unwrap_or(true)
            }
        }
        Value::Bool(value) => *value,
        _ => true,
    }
}

fn value_to_plain_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| value.to_string()),
    }
}

fn pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_string())
}
