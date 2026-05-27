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
- Stage 2.5b Prompt Guard-style injection specialist ensemble gate
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

## Detection Pipeline

```text
hardened_interceptor(agent_id, tool_name, tool_input)

┌─────────────────────────────────────────────────────────┐
│ L1.5 Hardening (hardening.py)                          │
│  0.  NFKC normalization                                │
│  0b. Zero-width character stripping (40+ chars)        │
│  0c. HTML/CSS hidden text detection                    │
│  1.  Heuristic fast-path                               │
│      score >= 0.7  → HEURISTIC_BLOCK (skip all ML)     │
│      score <= 0.05 → HEURISTIC_CLEAR (skip all ML)     │
│  2.  Classifier gate (critical >= 0.7)                 │
│  3.  decode_and_rescan (Base64/hex/ROT13, depth 5)     │
│  4.  Spotlight + canary                                │
│  5.  Cross-field correlation (threshold 0.65)          │
└──────────────────────┬──────────────────────────────────┘
                       │ UNCERTAIN (5-10% of calls)
┌──────────────────────▼──────────────────────────────────┐
│ Stage 1: Regex kill-switches (pre-compiled)             │
└──────────────────────┬──────────────────────────────────┘
                       │ PASS
┌──────────────────────▼──────────────────────────────────┐
│ Stage 2: TF-IDF + Random Forest                        │
│   BLOCK >= 0.85 → DENY                                  │
│   SAFE  <= 0.25 → ALLOW                                 │
│   UNCERTAIN     → Stage 2.5                             │
└──────────────────────┬──────────────────────────────────┘
                       │ UNCERTAIN
┌──────────────────────▼──────────────────────────────────┐
│ Stage 2.5a: DeBERTa-v3-base-injection                  │
│   DANGEROUS → DENY (immediate)                         │
│   SAFE      → ALLOW (immediate)                        │
│   UNCERTAIN → Stage 2.5b                               │
└──────────────────────┬──────────────────────────────────┘
                       │ UNCERTAIN only
┌──────────────────────▼──────────────────────────────────┐
│ Stage 2.5b: ProtectAI DeBERTa v2 (injection specialist)│
│   DANGEROUS → DENY                                     │
│   SAFE/UNCERTAIN → Stage 3                             │
│   UNAVAILABLE → Stage 3 (skip silently)                │
│   Controlled by: ASF_DISABLE_STAGE25B=true             │
└──────────────────────┬──────────────────────────────────┘
                       │ UNCERTAIN
┌──────────────────────▼──────────────────────────────────┐
│ Stage 3: LLM or ONNX (ASF_STAGE3_BACKEND=llm|onnx)    │
│   LLM:  Gemma 2B via Ollama (lazy init, fail-closed)   │
│   ONNX: Prompt Guard 86M (gravitee-io, 38ms, no auth)  │
│   UNCERTAIN → fail-closed (DENY)                       │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│ Output Guard (output_guard.py)                         │
└─────────────────────────────────────────────────────────┘
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| ASF_SKIP_LLM | false | Skip Stage 3 LLM entirely |
| ASF_ALWAYS_LLM | false | Force Stage 3 on every call |
| ASF_DISABLE_STAGE25 | false | Disable Stage 2.5a DeBERTa |
| ASF_DISABLE_STAGE25B | false | Disable Stage 2.5b Prompt Guard |
| ASF_DISABLE_L15 | false | Disable L1.5 hardening |
| ASF_DISABLE_FASTPATH | false | Disable heuristic fast-path |
| ASF_CLEAR_THRESHOLD | 0.05 | Heuristic score below which to CLEAR |
| ASF_SOFT_THRESHOLD | 0.10 | L1.5 score above which Stage 2 SAFE escalates to Stage 2.5; set 0.0 to disable |
| ASF_HEURISTIC_BLOCK | 0.7 | Heuristic score above which to BLOCK |
| ASF_STAGE3_BACKEND | llm | Stage 3 backend: llm or onnx |
| OLLAMA_BASE_URL | http://localhost:11434/v1 | Ollama endpoint |

## Performance

Latency (per tool call, smolagents integration):

```text
With fast-path (default): 14ms average
Without fast-path:        61ms average
Improvement:              77% latency reduction
```

Stage breakdown (when ML is invoked):

```text
L1.5 hardening:     <1ms
Stage 1 regex:      <1ms
Stage 2 TF-IDF:     6ms
Stage 2.5a DeBERTa: 57ms
Stage 2.5b Prompt Guard: 55ms (only on 2.5a UNCERTAIN)
Stage 3 Gemma 2B:   ~300ms (only on UNCERTAIN)
Stage 3 ONNX:       38ms   (only on UNCERTAIN)
```

External benchmark (deepset/prompt-injections, 546 samples):

```text
ASF full pipeline:     recall 13.3%, FPR 1.2%, F1 0.222
ONNX Prompt Guard 86M: recall 23.6%, FPR 0.3%, F1 0.381
Sigil heuristic (peer): recall 21.3%, FPR 0.0%, F1 0.351
```

## Production recommendation

For production containerization, Stage 2.5 should be extracted into small
FastAPI microservices with `/classify` endpoints. The ASF interceptor can call
those services with the normalized tool input and receive one of `SAFE`,
`DANGEROUS`, `UNCERTAIN`, or `UNAVAILABLE`.

Recommended deployment shape:

- `asf-api` or application process: runs the interceptor and registry client
- `stage25-deberta`: FastAPI service loading the HuggingFace model once at
  container startup
- `stage25b-promptguard`: optional FastAPI service for the Prompt Guard-style
  injection specialist
- `ollama` or `stage3-onnx`: Stage 3 fallback
- `langfuse` + `postgres`: observability stack

This preserves low cold-start impact by warming classifier models inside their
own long-lived containers, makes resource allocation explicit, and isolates ML
dependencies from the application runtime.
