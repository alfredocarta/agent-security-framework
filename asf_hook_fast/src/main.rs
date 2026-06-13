/// ASF fast-path Stage 1 hook  (D14)
///
/// Reads a Claude Code PreToolUse JSON payload from stdin, applies the same
/// regex patterns as policies.yaml Stage 1, and exits:
///   0  — no match, proceed to next hook (Python daemon pipeline)
///   2  — pattern matched, block with instructive message
///
/// On any parse or I/O error the binary exits 0 (fail-open) so the Python
/// hook can handle the event normally.
use std::io::{self, Read};

use regex::Regex;
use serde_json::Value;

// Stage 1 patterns mirrored from policies.yaml — keep in sync.
const STAGE1_PATTERNS: &[&str] = &[
    r"(?i)\bDROP\s+TABLE\b",
    r"(?i)\bDELETE\s+FROM\b",
    r"(?i)\bTRUNCATE\s+TABLE\b",
    r"(?i)\bDROP\s+DATABASE\b",
    r"(?i)\bSHUTDOWN\b",
    r"(?i)(;|\s)--",
    r"(?i)\bOR\s+1\s*=\s*1\b",
    r"(?i)\bUNION\s+SELECT\b",
    r"(?i)forget\s+(all\s+)?(your\s+)?(instructions|rules|policy)",
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)root\s+access",
    r"(?i)bypass\s+(security|policy|rules)",
];

// Single-command names that are safe without further inspection.
const SAFE_CMDS: &[&str] = &["ls", "cd", "pwd", "which", "type", "df"];

// Shell metacharacters that disqualify a Bash command from fast-pass.
const SHELL_META: &[char] = &[';', '&', '|', '`', '$', '<', '>', '(', ')', '\n', '\r'];

fn is_bash_passthrough(cmd: &str) -> bool {
    if cmd.chars().any(|c| SHELL_META.contains(&c)) {
        return false;
    }
    let first = cmd.split_whitespace().next().unwrap_or("");
    SAFE_CMDS.contains(&first)
}

fn extract_text(tool_name: &str, input: &Value) -> Option<String> {
    let s = |key: &str| -> &str {
        input.get(key).and_then(Value::as_str).unwrap_or("")
    };
    match tool_name {
        "Bash" => Some(s("command").to_string()),
        "Read" => Some(format!("path={}", s("file_path"))),
        "Write" => Some(format!("path={}\ncontent={}", s("file_path"), s("content"))),
        "Edit" | "MultiEdit" => Some(format!("path={}\nnew={}", s("file_path"), s("new_string"))),
        "Glob" | "Grep" => Some(format!("pattern={} path={}", s("pattern"), s("path"))),
        "WebFetch" => Some(format!("url={} prompt={}", s("url"), s("prompt"))),
        _ => None,
    }
}

fn block_message(tool_name: &str, pattern: &str) -> String {
    format!(
        "[ASF SECURITY BLOCK — Stage 1 fast-path]\n\
         Tool blocked: {tool_name}\n\
         Matched rule: {pattern}\n\
         \n\
         The tool call was NOT executed. Next steps:\n\
         1. Ask the user to explicitly review and approve this specific action.\n\
         2. Reformulate the request to avoid the flagged pattern.\n\
         3. If this is a false positive, the user can disable enforcement:\n\
              export ASF_HOOK_MONITOR_ONLY=true\n"
    )
}

fn main() {
    let mut raw = String::new();
    if io::stdin().read_to_string(&mut raw).is_err() {
        std::process::exit(0);
    }

    let payload: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => std::process::exit(0),
    };

    // PostToolUse events: always pass through (handled by Python hook).
    let event = payload
        .get("hook_event_name")
        .or_else(|| payload.get("event"))
        .and_then(Value::as_str)
        .unwrap_or("PreToolUse");
    if event == "PostToolUse" {
        std::process::exit(0);
    }

    let tool_name = payload
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let tool_input = payload.get("tool_input").cloned().unwrap_or(Value::Null);

    let text = match extract_text(tool_name, &tool_input) {
        Some(t) => t,
        None => std::process::exit(0),
    };

    if text.trim().is_empty() {
        std::process::exit(0);
    }

    if tool_name == "Bash" && is_bash_passthrough(&text) {
        std::process::exit(0);
    }

    // Compile patterns. In a short-lived process this runs once per invocation
    // (< 1 ms for 12 simple patterns).
    let compiled: Vec<Regex> = STAGE1_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    for (pattern_str, re) in STAGE1_PATTERNS.iter().zip(compiled.iter()) {
        if re.is_match(&text) {
            print!("{}", block_message(tool_name, pattern_str));
            std::process::exit(2);
        }
    }

    // No Stage 1 match — exit 0, Python hook handles the rest.
    std::process::exit(0);
}
