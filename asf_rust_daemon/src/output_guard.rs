use crate::canonical_log;
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

static SECRET_PATTERNS: OnceLock<[(Regex, &'static str); 9]> = OnceLock::new();

fn secret_patterns() -> &'static [(Regex, &'static str); 9] {
    SECRET_PATTERNS.get_or_init(|| {
        [
            (
                Regex::new(r"(?i)password\s*[:=]\s*\S+").expect("valid password_assignment regex"),
                "password_assignment",
            ),
            (
                Regex::new(r"(?i)api[_-]?key\s*[:=]\s*\S+").expect("valid api_key regex"),
                "api_key",
            ),
            (
                Regex::new(r"(?i)secret\s*[:=]\s*\S+").expect("valid secret regex"),
                "secret",
            ),
            (
                Regex::new(r"(?i)token\s*[:=]\s*\S+").expect("valid token regex"),
                "token",
            ),
            (
                Regex::new(r"(?i)private[_-]?key\s*[:=]\s*\S+").expect("valid private_key regex"),
                "private_key",
            ),
            (
                Regex::new(r"(?i)-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----")
                    .expect("valid pem_private_key regex"),
                "pem_private_key",
            ),
            (
                Regex::new(r"(?i)AKIA[0-9A-Z]{16}").expect("valid aws_access_key regex"),
                "aws_access_key",
            ),
            (
                Regex::new(r"(?i)sk-[0-9a-f]{32,}").expect("valid openai_api_key regex"),
                "openai_api_key",
            ),
            (
                Regex::new(r"(?i)ghp_[0-9a-zA-Z]{36}").expect("valid github_pat regex"),
                "github_pat",
            ),
        ]
    })
}

/// Inspect tool output for security issues.
/// Returns (is_dangerous, reason).
pub fn check_output(result: &str, canary: &str) -> (bool, String) {
    let out = if result.is_empty() {
        (false, String::new())
    } else if !canary.is_empty() && result.contains(canary) {
        (true, format!("Canary trap triggered: {canary}"))
    } else {
        let mut found: Option<(bool, String)> = None;
        for (pattern, name) in secret_patterns() {
            if pattern.is_match(result) {
                found = Some((true, format!("Secret detected: {name}")));
                break;
            }
        }
        found.unwrap_or_else(|| {
            if result.matches('{').count() > 10 {
                (
                    true,
                    "Potential bulk data exfiltration (>10 records)".to_string(),
                )
            } else {
                (false, String::new())
            }
        })
    };
    canonical_log::log(
        "output_guard",
        "rust",
        result,
        json!({"leaked": out.0, "reason": out.1}),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::check_output;

    #[test]
    fn detects_canary_before_secret_patterns() {
        assert_eq!(
            check_output("password = hunter2 CANARY", "CANARY"),
            (true, "Canary trap triggered: CANARY".to_string())
        );
    }

    #[test]
    fn detects_secret_patterns() {
        assert_eq!(
            check_output("api_key: abc123", ""),
            (true, "Secret detected: api_key".to_string())
        );
    }

    #[test]
    fn detects_bulk_data_after_secret_patterns() {
        assert_eq!(
            check_output("{}{}{}{}{}{}{}{}{}{}{}", ""),
            (
                true,
                "Potential bulk data exfiltration (>10 records)".to_string()
            )
        );
    }

    #[test]
    fn allows_empty_and_safe_output() {
        assert_eq!(check_output("", "CANARY"), (false, String::new()));
        assert_eq!(
            check_output("safe output", "CANARY"),
            (false, String::new())
        );
    }
}
