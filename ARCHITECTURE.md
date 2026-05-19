# Agent Security Framework Runtime Architecture

## Docker services

`~/Projects/langfuse-compose.yml` defines the observability stack:

- `langfuse`: `langfuse/langfuse:2`, exposed on `localhost:3000`
- `postgres`: `postgres:15`, backing store for Langfuse

At verification time, `docker ps` could not connect to the local Docker daemon:

```text
Cannot connect to the Docker daemon at unix:///Users/alfredo/.docker/run/docker.sock. Is the docker daemon running?
```

The compose file confirms the intended Docker footprint is Langfuse plus Postgres only.

## Host services

The ASF security pipeline runs on the macOS host inside the `eval-framework`
conda environment. This includes:

- `hardened_interceptor` and the L1.5 hardening layers
- Stage 1 regex kill switches
- Stage 2 TF-IDF + Random Forest classifier
- Stage 2.5 DeBERTa classifier
- Stage 3 semantic LLM calls to Ollama
- SQLite registry and audit trail

DeBERTa was confirmed to load from the host Python process:

```bash
cd ~/Projects/agent-security-framework
conda run -n eval-framework python -c "from stage25_deberta import _get_model; m = _get_model(); print('model loaded on host')"
```

Output:

```text
[STAGE 2.5] DeBERTa warm-up complete
model loaded on host
```

Ollama also runs on the host at `localhost:11434` and serves `gemma2:2b` for
Stage 3.

## Why DeBERTa runs on the host today

DeBERTa is loaded through HuggingFace Transformers in the same Python process as
the interceptor. Keeping it on the host gives the current evaluation harness:

- direct access to the local HuggingFace model cache
- no network hop between Stage 2 and Stage 2.5
- low-latency in-process inference after warm-up
- simpler dependency management for the conda-based evaluation workflow

## Production recommendation

For production containerization, Stage 2.5 should be extracted into a small
FastAPI microservice with a `/classify` endpoint. The ASF interceptor can call
that service with the normalized tool input and receive one of `SAFE`,
`DANGEROUS`, or `UNCERTAIN`.

Recommended deployment shape:

- `asf-api` or application process: runs the interceptor and registry client
- `stage25-deberta`: FastAPI service loading the HuggingFace model once at
  container startup
- `ollama` or managed LLM endpoint: Stage 3 fallback
- `langfuse` + `postgres`: observability stack

This preserves low cold-start impact by warming DeBERTa inside its own long-lived
container, makes resource allocation explicit, and isolates ML dependencies from
the application runtime.
