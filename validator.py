from key_authority import KA
from registry import get_agent_permissions
from interceptor import _stage1_regex, _stage2_classifier, _stage3_llm, _load_policies
from audit import AUDITOR
import re
import canonical_log

DELEGATION_PATTERNS = [
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
]

def _check_delegation(sender_id, message):
    for pattern in DELEGATION_PATTERNS:
        if re.search(pattern, message):
            return True, pattern

    policies = _load_policies()
    sender_permissions = get_agent_permissions(sender_id)
    all_tools = set()
    for agent_config in policies["agents"].values():
        all_tools.update(agent_config["permissions"])

    restricted_tools = all_tools - set(sender_permissions)
    for tool in restricted_tools:
        if re.search(rf"(?i)\b{re.escape(tool)}\b", message):
            return True, f"message references restricted tool '{tool}'"

    return False, None

def validate_inter_agent_message(sender_id, receiver_id, message, signature):
    print(f"\n[VALIDATOR] Validating message: {sender_id} -> {receiver_id}")
    def _canon_return(valid, reason):
        canonical_log.log("validate_message", "py", message, {"valid": valid, "reason": reason})
        return valid, reason
    AUDITOR.log_event(sender_id, "inter_agent_message", "VALIDATOR_START", f"Validating message to {receiver_id}")

    if not KA.verify_signature(sender_id, message, signature):
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "Invalid signature")
        return _canon_return(False, "CRITICAL ERROR: Invalid signature - possible impersonation attempt.")
    AUDITOR.log_event(sender_id, "inter_agent_message", "SIGNATURE_OK", "Ed25519 signature verified")

    allowed_tools = get_agent_permissions(sender_id)
    if not allowed_tools:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "Agent suspended or not found")
        return _canon_return(False, "ACCESS DENIED: Sender agent is suspended.")

    if "communication" not in allowed_tools:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "No communication permission")
        return _canon_return(False, f"ACCESS DENIED: {sender_id} does not have communication permission.")

    is_delegation, matched = _check_delegation(sender_id, message)
    if is_delegation:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", f"Delegation attack: {matched}")
        return _canon_return(False, f"DELEGATION ATTACK BLOCKED: {matched}.")

    AUDITOR.log_event(sender_id, "inter_agent_message", "STAGE_1_START", "Regex pattern analysis")
    is_dangerous, matched_pattern = _stage1_regex(message)
    if is_dangerous:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", f"Stage 1 regex match: {matched_pattern}")
        return _canon_return(False, f"MESSAGE BLOCKED: dangerous pattern detected ({matched_pattern}).")
    AUDITOR.log_event(sender_id, "inter_agent_message", "STAGE_1_PASS", "No dangerous pattern matched")

    AUDITOR.log_event(sender_id, "inter_agent_message", "STAGE_2_START", "ML classifier analysis")
    verdict, confidence = _stage2_classifier(message)
    if verdict == "DANGEROUS":
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", f"Stage 2 BLOCK: DANGEROUS (confidence: {confidence:.2f})")
        return _canon_return(False, f"MESSAGE BLOCKED: classifier flagged as dangerous (confidence: {confidence:.2f}).")
    if verdict == "SAFE":
        AUDITOR.log_event(sender_id, "inter_agent_message", "ALLOWED", f"Stage 2 PASS: SAFE (confidence: {confidence:.2f}) - delivered to {receiver_id}")
        return _canon_return(True, "Message validated and safe.")

    AUDITOR.log_event(sender_id, "inter_agent_message", "STAGE_2_UNCERTAIN", f"Classifier uncertain (confidence: {confidence:.2f}), escalating")
    AUDITOR.log_event(sender_id, "inter_agent_message", "STAGE_3_START", "LLM semantic analysis")
    if _stage3_llm(message):
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "Stage 3 LLM flagged as dangerous")
        return _canon_return(False, "MESSAGE BLOCKED: semantic analysis flagged this message as dangerous.")

    AUDITOR.log_event(sender_id, "inter_agent_message", "ALLOWED", f"Stage 3 LLM cleared - delivered to {receiver_id}")
    return _canon_return(True, "Message validated and safe.")
