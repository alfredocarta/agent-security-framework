from key_authority import KA
from registry import get_agent_permissions
from interceptor import _stage1_regex, _stage3_llm
from audit import AUDITOR

def validate_inter_agent_message(sender_id, receiver_id, message, signature):
    print(f"\n[VALIDATOR] Validating message: {sender_id} -> {receiver_id}")

    # Step 1 - cryptographic verification
    if not KA.verify_signature(sender_id, message, signature):
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "Invalid signature")
        return False, "CRITICAL ERROR: Invalid signature - possible impersonation attempt."
    print("[VALIDATOR] Signature verified.")

    # Step 2 - permission check: sender must have communication rights
    allowed_tools = get_agent_permissions(sender_id)
    if not allowed_tools:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "Agent suspended")
        return False, "ACCESS DENIED: Sender agent is suspended."

    if "communication" not in allowed_tools:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "No communication permission")
        return False, f"ACCESS DENIED: {sender_id} does not have communication permission."

    # Step 3 - intent analysis (no kill switch - observe only)
    is_dangerous, matched_pattern = _stage1_regex(message)
    if is_dangerous:
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", f"Regex match: {matched_pattern}")
        return False, f"MESSAGE BLOCKED: dangerous pattern detected ({matched_pattern})."

    if _stage3_llm(message):
        AUDITOR.log_event(sender_id, "inter_agent_message", "BLOCKED", "Semantic threat in inter-agent message")
        return False, "MESSAGE BLOCKED: semantic analysis flagged this message as dangerous."

    AUDITOR.log_event(sender_id, "inter_agent_message", "ALLOWED", f"Safe message to {receiver_id}")
    return True, "Message validated and safe."
