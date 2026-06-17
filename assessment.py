TEMPLATES = {
    "AGENT_SUSPENDED": "The agent is currently suspended and cannot execute tool calls.",
    "TOOL_NOT_PERMITTED": "This tool is not in the agent's allowed permission list.",
    "ALLOWLIST_CLEAR": "This tool call targets a path on the read-only allowlist and was authorized without further inspection.",
    "HEURISTIC_BLOCK": "The fast-path heuristic filter flagged this request as suspicious (score: {score}).",
    "HEURISTIC_CLEAR": "The quick-screening filter found no suspicious patterns (risk score: {score}). The request was cleared as low-risk.",
    "REGEX_BLOCK": "The request matched a known attack pattern ({pattern}). The tool call was blocked immediately.",
    "STAGE2_BLOCK": "The statistical classifier rated this request as dangerous (confidence: {confidence}). The tool call was blocked.",
    "STAGE2_CLEAR": "The statistical classifier found no signs of malicious intent (confidence: {confidence}). The request was cleared.",
    "STAGE3_LLM_BLOCK_CONFIRM": "The LLM reviewer confirmed this request is dangerous. The tool call was blocked.",
    "STAGE3_LLM_CLEAR": "The LLM reviewer confirmed this request is within acceptable boundaries. The request was cleared.",
    "STAGE25_DEBERTA_BLOCK": "Content analysis detected a high-risk pattern (confidence: {confidence}). The tool call was blocked.",
    "STAGE25_DEBERTA_CLEAR": "Content analysis found no signs of malicious intent. The request was cleared.",
    "STAGE25B_BLOCK": "The injection guard detected a prompt injection attempt. The tool call was blocked.",
    "STAGE25B_CLEAR": "The injection guard found no prompt injection attempt. The request was cleared.",
    "STAGE3_ONNX_BLOCK": "The ONNX prompt scanner flagged this input as potentially malicious. The tool call was blocked.",
    "STAGE3_ONNX_CLEAR": "The ONNX prompt scanner confirmed this input is safe. The request was cleared.",
    "STAGE3_ONNX_UNCERTAIN": "The ONNX scanner returned an uncertain result. The request was blocked as a precaution.",
    "STAGE3_ONNX_ERROR": "An error occurred in the ONNX scanner. The request was blocked as a precaution.",
    "STAGE3_LLM_BLOCK": "The LLM reviewer flagged this request as potentially harmful. The tool call was blocked.",
    "HITL_REQUESTED": "The LLM reviewer flagged this request as potentially harmful. A human operator must approve or block this action.",
    "HITL_CLEAR": "The LLM reviewer confirmed this request is within acceptable boundaries. The request was cleared.",
}


def build_assessment(scenario: str, **kwargs) -> str:
    template = TEMPLATES.get(scenario)
    if template is None:
        return f"Security assessment: {scenario}."
    try:
        return template.format(**kwargs)
    except KeyError:
        return template
