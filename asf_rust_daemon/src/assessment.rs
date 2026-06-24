use std::collections::HashMap;

fn template_for(scenario: &str) -> Option<&'static str> {
    match scenario {
        "AGENT_SUSPENDED" => Some("The agent is currently suspended and cannot execute tool calls."),
        "TOOL_NOT_PERMITTED" => Some("This tool is not in the agent's allowed permission list."),
        "ALLOWLIST_CLEAR" => Some("This tool call targets a path on the read-only allowlist and was authorized without further inspection."),
        "HEURISTIC_BLOCK" => Some("The fast-path heuristic filter flagged this request as suspicious (score: {score})."),
        "HEURISTIC_CLEAR" => Some("The quick-screening filter found no suspicious patterns (risk score: {score}). The request was cleared as low-risk."),
        "REGEX_BLOCK" => Some("The request matched a known attack pattern ({pattern}). The tool call was blocked immediately."),
        "STAGE2_BLOCK" => Some("The statistical classifier rated this request as dangerous (confidence: {confidence}). The tool call was blocked."),
        "STAGE2_CLEAR" => Some("The statistical classifier found no signs of malicious intent (confidence: {confidence}). The request was cleared."),
        "STAGE3_LLM_BLOCK_CONFIRM" => Some("The LLM reviewer confirmed this request is dangerous. The tool call was blocked."),
        "STAGE3_LLM_CLEAR" => Some("The LLM reviewer confirmed this request is within acceptable boundaries. The request was cleared."),
        "STAGE25_DEBERTA_BLOCK" => Some("Content analysis detected a high-risk pattern (confidence: {confidence}). The tool call was blocked."),
        "STAGE25_DEBERTA_CLEAR" => Some("Content analysis found no signs of malicious intent. The request was cleared."),
        "STAGE25B_BLOCK" => Some("The injection guard detected a prompt injection attempt. The tool call was blocked."),
        "STAGE25B_CLEAR" => Some("The injection guard found no prompt injection attempt. The request was cleared."),
        "STAGE3_ONNX_BLOCK" => Some("The ONNX prompt scanner flagged this input as potentially malicious. The tool call was blocked."),
        "STAGE3_ONNX_CLEAR" => Some("The ONNX prompt scanner confirmed this input is safe. The request was cleared."),
        "STAGE3_ONNX_UNCERTAIN" => Some("The ONNX scanner returned an uncertain result. The request was blocked as a precaution."),
        "STAGE3_ONNX_ERROR" => Some("An error occurred in the ONNX scanner. The request was blocked as a precaution."),
        "STAGE3_LLM_BLOCK" => Some("The LLM reviewer flagged this request as potentially harmful. The tool call was blocked."),
        "HITL_REQUESTED" => Some("The LLM reviewer flagged this request as potentially harmful. A human operator must approve or block this action."),
        "HITL_CLEAR" => Some("The LLM reviewer confirmed this request is within acceptable boundaries. The request was cleared."),
        _ => None,
    }
}

pub fn build_assessment(scenario: &str, params: &HashMap<&str, &str>) -> String {
    let Some(template) = template_for(scenario) else {
        return format!("Security assessment: {}.", scenario);
    };

    let mut rendered = template.to_string();
    for (key, value) in params {
        let placeholder = format!("{{{}}}", key);
        rendered = rendered.replace(&placeholder, value);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::build_assessment;
    use std::collections::HashMap;

    #[test]
    fn returns_template_without_params() {
        let params = HashMap::new();
        assert_eq!(
            build_assessment("AGENT_SUSPENDED", &params),
            "The agent is currently suspended and cannot execute tool calls."
        );
    }

    #[test]
    fn replaces_placeholders_from_params() {
        let mut params = HashMap::new();
        params.insert("score", "0.92");
        assert_eq!(
            build_assessment("HEURISTIC_BLOCK", &params),
            "The fast-path heuristic filter flagged this request as suspicious (score: 0.92)."
        );
    }

    #[test]
    fn leaves_missing_placeholders_unchanged() {
        let params = HashMap::new();
        assert_eq!(
            build_assessment("HEURISTIC_BLOCK", &params),
            "The fast-path heuristic filter flagged this request as suspicious (score: {score})."
        );
    }

    #[test]
    fn returns_fallback_for_unknown_scenario() {
        let params = HashMap::new();
        assert_eq!(
            build_assessment("UNKNOWN", &params),
            "Security assessment: UNKNOWN."
        );
    }
}
