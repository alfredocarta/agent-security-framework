from typing import TypedDict, List
from langgraph.graph import StateGraph, END
import interceptor
from key_authority import KA

class AgentState(TypedDict):
    agent_id: str
    request: str
    tool: str
    tool_input: str
    signature: bytes
    security_decision: bool
    log: List[str]

def agent_node(state: AgentState):
    message = f"{state['tool']}:{state['tool_input']}"
    signature = KA.sign_message(state['agent_id'], message)
    return {
        "signature": signature,
        "log": state['log'] + [f"Signed request created for tool '{state['tool']}'"]
    }

def security_node(state: AgentState):
    message = f"{state['tool']}:{state['tool_input']}"

    if not KA.verify_signature(state['agent_id'], message, state['signature']):
        return {
            "security_decision": False,
            "log": state['log'] + ["IDENTITY BLOCK: invalid signature - possible impersonation attempt."]
        }

    is_safe, reason = interceptor.security_interceptor(
        state['agent_id'],
        state['tool'],
        state['tool_input']
    )
    return {
        "security_decision": is_safe,
        "log": state['log'] + [f"Security decision: {reason}"]
    }

def execution_node(state: AgentState):
    if not state['security_decision']:
        return {"log": state['log'] + ["Execution cancelled by security system."]}
    return {"log": state['log'] + [f"Tool '{state['tool']}' executed successfully."]}

workflow = StateGraph(AgentState)
workflow.add_node("agent", agent_node)
workflow.add_node("security", security_node)
workflow.add_node("executor", execution_node)
workflow.set_entry_point("agent")
workflow.add_edge("agent", "security")
workflow.add_edge("security", "executor")
workflow.add_edge("executor", END)
app = workflow.compile()
