use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub session_id: Option<String>,
    pub transcript_path: Option<String>,
    pub tool_use_id: Option<String>,
    pub agent_id: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    #[allow(dead_code)]
    Allow,
    Deny,
    Uncertain,
}

#[derive(Debug, Serialize)]
pub struct CheckResponse {
    pub verdict: Verdict,
    pub reason: String,
}
