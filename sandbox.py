import docker
import logging

logger = logging.getLogger(__name__)

class ToolSandbox:
    def __init__(self, image="python:3.11-alpine"):
        self.image = image
        try:
            self.client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker non disponibile, impossibile isolare i tool: {e}")
            self.client = None

    def execute(self, code: str) -> str:
        if not self.client:
            raise RuntimeError("Ambiente Docker non disponibile per il sandboxing.")
        
        try:
            # Esegue il codice in un container effimero e isolato
            container_logs = self.client.containers.run(
                self.image,
                command=["python", "-c", code],
                network_disabled=True,     # Nessun accesso a internet per impedire esfiltrazione
                remove=True,               # Il container viene distrutto subito dopo l'esecuzione
                mem_limit="128m",          # Limite RAM
                cpu_quota=50000,           # Limite CPU (circa 50% di un core)
                stdout=True,
                stderr=True,
                environment={"ASF_SANDBOX": "true"}
            )
            return container_logs.decode('utf-8').strip()
        except docker.errors.ContainerError as e:
            return f"Sandbox Error: {e.stderr.decode('utf-8').strip()}"
        except Exception as e:
            return f"Execution Failed: {str(e)}"
