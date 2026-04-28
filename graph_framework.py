from typing import TypedDict, List
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
import interceptor
from key_authority import KA

class AgentState(TypedDict):
    agent_id: str
    request: str
    tool: str
    tool_input: str
    signature: bytes
    security_decision: str
    log: List[str]

def agent_node(state: AgentState):
    message = f"{state['tool']}:{state['tool_input']}"
    signature = KA.sign_message(state['agent_id'], message)
    return {
        "signature": signature,
        "log": state.get('log', []) + [f"Signed request created for tool '{state['tool']}'"]
    }

def security_node(state: AgentState):
    message = f"{state['tool']}:{state['tool_input']}"

    if not KA.verify_signature(state['agent_id'], message, state['signature']):
        return {
            "security_decision": "DENY",
            "log": state.get('log', []) + ["IDENTITY BLOCK: invalid signature - possible impersonation attempt."]
        }

    decision, reason = interceptor.security_interceptor(
        state['agent_id'],
        state['tool'],
        state['tool_input']
    )
    return {
        "security_decision": decision,
        "log": state.get('log', []) + [f"Security decision: {reason}"]
    }

def human_approval_node(state: AgentState):
    decision = state.get('security_decision')
    return {"log": state.get('log', []) + [f"Human review completed. Final decision: {decision}"]}

def execution_node(state: AgentState):
    if state.get('security_decision') != "ALLOW":
        return {"log": state.get('log', []) + ["Execution cancelled by security system or human."]}
    return {"log": state.get('log', []) + [f"Tool '{state['tool']}' executed successfully."]}

def route_after_security(state: AgentState):
    if state.get('security_decision') == "HITL":
        return "human"
    elif state.get('security_decision') == "ALLOW":
        return "executor"
    else:
        return END

def route_after_human(state: AgentState):
    if state.get('security_decision') == "ALLOW":
        return "executor"
    return END

workflow = StateGraph(AgentState)
workflow.add_node("agent", agent_node)
workflow.add_node("security", security_node)
workflow.add_node("human", human_approval_node)
workflow.add_node("executor", execution_node)

workflow.set_entry_point("agent")
workflow.add_edge("agent", "security")
workflow.add_conditional_edges("security", route_after_security)
workflow.add_conditional_edges("human", route_after_human)
workflow.add_edge("executor", END)

memory = MemorySaver()
app = workflow.compile(checkpointer=memory, interrupt_before=["human"])
