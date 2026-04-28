import os
from graph_framework import app

def run_hitl_demo():
    config = {"configurable": {"thread_id": "demo_session_45"}}
    
    print("\n[DEMO] Iniezione dello stato per simulare il blocco di sicurezza...")
    
    state = {
        "agent_id": "demo_agent",
        "tool": "data_export",
        "tool_input": "export_all_users()",
        "security_decision": "HITL",
        "log": ["Security Interceptor: Semantic attack flagged. HITL Requested."]
    }
    
    # Inietta lo stato. LangGraph calcola i path e si FERMA prima di 'human'
    app.update_state(config, state, as_node="security")

    state_snapshot = app.get_state(config)
    print(f"\n[STATO] Esecuzione in pausa? {'Sì' if len(state_snapshot.next) > 0 else 'No'}")
    print(f"[STATO] Prossimo nodo in coda: {state_snapshot.next}")
    print(f"[STATO] Decisione attuale: {state_snapshot.values.get('security_decision')}")

    print("\n[AZIONE] 👨‍💻 Il revisore umano sta approvando l'azione (update_state)...")
    
    # LA CORREZIONE: Aggiungiamo as_node="human" così LangGraph sa chi ha prodotto la modifica 
    # e sa che deve proseguire dal percorso successivo a 'human'.
    app.update_state(config, {"security_decision": "ALLOW"}, as_node="human")
    
    print("\n[AZIONE] Ripresa dell'esecuzione del grafo (app.stream)...")
    
    for event in app.stream(None, config, stream_mode="values"):
        pass
        
    final_state = app.get_state(config)
    print("\n[RISULTATO FINALE] Log di Esecuzione:")
    for log_entry in final_state.values.get("log", []):
        print(f" -> {log_entry}")

if __name__ == "__main__":
    run_hitl_demo()
