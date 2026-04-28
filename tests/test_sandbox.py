import pytest
from sandbox import ToolSandbox

def test_sandbox_execution():
    sandbox = ToolSandbox()
    if not sandbox.client:
        pytest.skip("Docker non in esecuzione sul sistema host. Skip test sandbox.")
    
    # Test 1: Esecuzione standard sicura
    result = sandbox.execute("print('Hello from Sandbox')")
    assert "Hello from Sandbox" in result

    # Test 2: Verifica isolamento rete (deve fallire la richiesta HTTP)
    code = "import urllib.request; urllib.request.urlopen('http://example.com')"
    result_network = sandbox.execute(code)
    
    # Ci aspettiamo un errore dalla sandbox poiché non c'è rete
    assert "Sandbox Error" in result_network or "Execution Failed" in result_network
