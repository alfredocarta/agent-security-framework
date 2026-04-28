from key_authority import KA
from registry import get_agent_permissions
from interceptor import _stage1_regex, _stage3_llm, _load_policies
from audit import AUDITOR
import re

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
            return True, f"message references restricted tool {toolrm agents_registry.db audit_log.json}"

    return False, None

def validate_inter_agent_message(sender_id, receiver_id, message, signature):
    print(f"
[VALIDATOR] Validating message: {sender_id} -> {receiver_id}")

    if not KA.verify_signature(sender_id, message, signature):
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "Invalid signature")
        return False, "CRITICAL ERROR: Invalid signature - possible impersonation attempt."
    print("[VALIDATOR] Signature verified.")

    allowed_tools = get_agent_permissions(sender_id)
    if not allowed_tools:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "Agent suspended")
        return False, "ACCESS DENIED: Sender agent is suspended."

    if "communication" not in allowed_tools:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "No communication permission")
        return False, f"ACCESS DENIED: {sender_id} does not have communication permission."

    is_delegation, matched = _check_delegation(sender_id, message)
    if is_delegation:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", f"Delegation attack detected: {matched}")
        return False, f"DELEGATION ATTACK BLOCKED: {matched}."

    is_dangerous, matched_pattern = _stage1_regex(message)
    if is_dangerous:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", f"Regex match: {matched_pattern}")
        return False, f"MESSAGE BLOCKED: dangerous pattern detected ({matched_pattern})."

    if _stage3_llm(message):
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "Semantic threat in inter-agent message")
        return False, "MESSAGE BLOCKED: semantic analysis flagged this message as dangerous."

    AUDITOR.log_event(sender_id, "inter_agent_message", "ALLOWED", f"Safe message to {receiver_id}")
    return True, "Message validated and safe."
