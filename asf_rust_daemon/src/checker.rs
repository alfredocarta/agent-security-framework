use crate::hardening;
use crate::patterns::{KILL_SWITCH_PATTERNS, SEMANTIC_PROBE_PATTERNS};
use crate::protocol::Verdict;
use std::borrow::Cow;

pub fn check(tool_input: &serde_json::Value) -> (Verdict, &'static str, &'static str, String) {
    let extracted = extract_tool_input_text(tool_input);
    let extracted_text = extracted.into_owned();

    if KILL_SWITCH_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(&extracted_text))
    {
        return (
            Verdict::Deny,
            "stage1_kill_switch",
            "KILL_SWITCH",
            extracted_text,
        );
    }

    if SEMANTIC_PROBE_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(&extracted_text))
    {
        return (
            Verdict::Deny,
            "stage1_semantic_probe",
            "KILL_SWITCH",
            extracted_text,
        );
    }

    let (is_deny, reason, db_outcome) = hardening::l1_5_check(&extracted_text);
    if is_deny {
        return (Verdict::Deny, reason, db_outcome, extracted_text);
    }

    (Verdict::Uncertain, "stage1_no_match", "", extracted_text)
}

fn extract_tool_input_text(tool_input: &serde_json::Value) -> Cow<'_, str> {
    for key in ["command", "new_string", "new_source", "content", "pattern", "prompt", "file_path", "path"] {
        if let Some(value) = tool_input[key].as_str() {
            return Cow::Borrowed(value);
        }
    }

    Cow::Owned(serde_json::to_string(tool_input).unwrap_or_default())
}
