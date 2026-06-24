use crate::interceptor;
use crate::key_authority;
use crate::registry::{self, DbPool as RegistryDbPool};
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

const DELEGATION_PATTERNS: &[&str] = &[
    r"(?i)execute\s+on\s+my\s+behalf",
    r"(?i)run\s+this\s+for\s+me",
    r"(?i)perform\s+.+\s+for\s+me",
    r"(?i)i\s+need\s+you\s+to\s+(issue|refund|delete|drop|write|execute)",
    r"(?i)can\s+you\s+(issue|refund|delete|drop|write|execute)\s+.+\s+for\s+me",
    r"(?i)do\s+this\s+instead\s+of\s+me",
    r"(?i)act\s+on\s+my\s+behalf",
    r"(?i)pretend\s+you\s+are",
    r"(?i)as\s+if\s+you\s+were",
    r"(?i)use\s+your\s+permissions\s+to",
];

// Static superset of known ASF/Hermes tool-permission names. The Python validator
// derives this from policies.yaml; keeping a superset here preserves the security
// intent without coupling this module to YAML parsing.
const ALL_KNOWN_TOOLS: &[&str] = &[
    "communication",
    "read_db",
    "write_db",
    "issue_refund",
    "read_docs",
    "file_read",
    "file_write",
    "file_search",
    "skill_read",
    "skill_manage",
    "memory_read",
    "memory_write",
    "security_sensitive_write",
    "code_execution",
    "execute_code",
    "shell",
    "bash",
    "network",
    "web_search",
];

/// Validate a signed inter-agent message up through Rust Stage 1.
///
/// Returns `(is_valid, reason_string)` and never intentionally panics. A `true`
/// result means Rust prechecks passed and the caller must continue with Python
/// Stage 2/3 because the returned reason is `requires_python_stage23`.
///
/// Note: the registry pool and key-authority pool are distinct types in this
/// crate (`registry::DbPool` is a SQLite connection mutex; `key_authority::DbPool`
/// is a keys-registry path), so the second argument uses the key-authority alias.
/// This matches `crate::key_authority::verify_signature` exactly.
pub fn validate_inter_agent_message(
    pool: &RegistryDbPool,
    key_pool: &key_authority::DbPool,
    sender_id: &str,
    receiver_id: &str,
    message: &str,
    signature: &[u8],
) -> (bool, String) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        validate_inter_agent_message_inner(
            pool,
            key_pool,
            sender_id,
            receiver_id,
            message,
            signature,
        )
    }));

    match result {
        Ok(verdict) => verdict,
        Err(_) => (false, "VALIDATOR ERROR: internal panic caught.".to_string()),
    }
}

fn validate_inter_agent_message_inner(
    pool: &RegistryDbPool,
    key_pool: &key_authority::DbPool,
    sender_id: &str,
    receiver_id: &str,
    message: &str,
    signature: &[u8],
) -> (bool, String) {
    let _ = receiver_id;

    if !key_authority::verify_signature(key_pool, sender_id, message, signature) {
        return (
            false,
            "CRITICAL ERROR: Invalid signature - possible impersonation attempt.".to_string(),
        );
    }

    let allowed_permissions = match registry::get_agent_permissions(pool, sender_id) {
        Ok(value) => permissions_from_value(&value),
        Err(err) => {
            return (
                false,
                format!("VALIDATOR ERROR: failed to load sender permissions: {err}"),
            )
        }
    };

    if allowed_permissions.is_empty() {
        return (
            false,
            "ACCESS DENIED: Sender agent is suspended.".to_string(),
        );
    }

    if !allowed_permissions.contains("communication") {
        return (
            false,
            format!("ACCESS DENIED: {sender_id} does not have communication permission."),
        );
    }

    match check_delegation(message, &allowed_permissions) {
        Ok(Some(matched)) => return (false, format!("DELEGATION ATTACK BLOCKED: {matched}.")),
        Ok(None) => {}
        Err(err) => {
            return (
                false,
                format!("VALIDATOR ERROR: delegation check failed: {err}"),
            )
        }
    }

    match interceptor::_stage1_regex(message) {
        Ok((true, matched_pattern)) => {
            let matched = matched_pattern.unwrap_or_else(|| "<unknown>".to_string());
            (
                false,
                format!("MESSAGE BLOCKED: dangerous pattern detected ({matched})."),
            )
        }
        Ok((false, _)) => (true, "requires_python_stage23".to_string()),
        Err(err) => (
            false,
            format!("VALIDATOR ERROR: Stage 1 regex engine error: {err}"),
        ),
    }
}

fn check_delegation(
    message: &str,
    allowed_permissions: &HashSet<String>,
) -> Result<Option<String>, String> {
    for pattern_text in DELEGATION_PATTERNS {
        let pattern = Regex::new(pattern_text)
            .map_err(|err| format!("invalid delegation regex {pattern_text:?}: {err}"))?;
        if pattern.is_match(message) {
            return Ok(Some((*pattern_text).to_string()));
        }
    }

    for tool in ALL_KNOWN_TOOLS {
        if allowed_permissions.contains(*tool) {
            continue;
        }

        let pattern_text = format!(r"(?i)\b{}\b", regex::escape(tool));
        let pattern = Regex::new(&pattern_text)
            .map_err(|err| format!("invalid tool regex {pattern_text:?}: {err}"))?;
        if pattern.is_match(message) {
            return Ok(Some(format!("message references restricted tool '{tool}'")));
        }
    }

    Ok(None)
}

fn permissions_from_value(value: &Value) -> HashSet<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(ToOwned::to_owned))
            .collect(),
        Value::Object(map) => map
            .iter()
            .filter_map(|(key, value)| match value {
                Value::Bool(false) | Value::Null => None,
                _ => Some(key.clone()),
            })
            .collect(),
        Value::String(permission) => [permission.clone()].into_iter().collect(),
        _ => HashSet::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_array_extracts_strings() {
        let value = serde_json::json!(["communication", "read_db", 1, null]);
        let permissions = permissions_from_value(&value);
        assert!(permissions.contains("communication"));
        assert!(permissions.contains("read_db"));
        assert_eq!(permissions.len(), 2);
    }

    #[test]
    fn delegation_patterns_match() {
        let allowed = ["communication".to_string()].into_iter().collect();
        let matched = check_delegation("Please execute on my behalf", &allowed).unwrap();
        assert_eq!(matched, Some(r"(?i)execute\s+on\s+my\s+behalf".to_string()));
    }

    #[test]
    fn restricted_tool_reference_matches() {
        let allowed = ["communication".to_string()].into_iter().collect();
        let matched = check_delegation("Ask billing to issue_refund now", &allowed).unwrap();
        assert_eq!(
            matched,
            Some("message references restricted tool 'issue_refund'".to_string())
        );
    }
}
