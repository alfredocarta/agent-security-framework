# API-key security verification

Scope: focused static audit of provider API-key handling and automated red-team regressions for API-key exfiltration.

## Current status

- GAP-APIKEY-005 fixed: supervised agent launch paths scrub provider and ASF secret variables from the child environment before exec/spawn.
- GAP-APIKEY-001/002/003 fixed: model/output previews, trace stores, audit rows, dashboard rendering, and canonical logs now apply centralized sink-level redaction.
- GAP-APIKEY-004 remains a known residual: character-by-character or shape-probe exfiltration can disclose fragments without ever emitting a full key-shaped secret. The regression remains xfail with this rationale.

## Secret environment boundary (GAP-APIKEY-005)

ASF now removes this denylist before launching the supervised agent or agent-owned tool subprocesses:

- `OPENROUTER_API_KEY`
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `GROQ_API_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_PUBLIC_KEY`
- `ASF_MASTER_KEY`
- `ASF_DASHBOARD_PASSWORD`

Operators can extend the denylist with `ASF_SCRUB_ENV_VARS`, a comma-separated list of additional variable names.

Applied launch paths:

- `wrapper/hermes_mvp.py`: builds the Hermes child env, writes the OpenRouter key to an owner-only Stage 3 key file when needed, then scrubs the child env before `subprocess.call(..., env=env)`.
- `asf_rust_daemon/src/wrapper.rs` (`asf-run`): starts/ensures the ASF daemon first, then calls `env_remove()` for the denylist/custom list on the supervised agent `Command` before `exec()`.
- `wrapper/asf_container_launch.py`: Docker env construction scrubs the explicit env map before converting it to `-e KEY=VALUE` args.
- `wrapper/langgraph_mvp.py` and `wrapper/asf_core.py`: non-sandboxed LangGraph tool subprocesses and sandboxed Hermes tool subprocesses receive scrubbed envs as defense in depth.
- `install.sh`: does not launch a supervised agent; no runtime env inheritance fix is needed there beyond installing the updated `asf-run` binary.

### Stage 3 OpenRouter key handling after scrubbing

There are two current execution modes:

1. `asf-run`: the Rust wrapper ensures the ASF daemon/hook runtime is running before execing the supervised agent. The daemon process may retain provider credentials needed by Stage 3; the subsequently execed agent has the scrubbed environment and cannot read those variables through `env`/`printenv`/`os.environ`.
2. `wrapper/hermes_mvp.py`: the ASF pipeline runs in-process with the supervised Hermes plugin path. To avoid re-exporting `OPENROUTER_API_KEY` into the agent-visible environment, the wrapper lazily moves the value to an owner-only file under `~/.cache/asf/secrets/openrouter_api_key` (or `ASF_SECRET_DIR`) with `0600` permissions and passes only `ASF_OPENROUTER_API_KEY_FILE`. `interceptor.py:_read_openrouter_api_key()` reads that file at OpenRouter client construction time and never re-exports the key.

This keeps Stage 3 authentication working after env scrubbing. The red-team suite includes an explicit regression that deletes `OPENROUTER_API_KEY` from the environment and verifies `_read_openrouter_api_key()` still loads the key from a chmod-600 file.

## Centralized redaction (GAP-APIKEY-001/002/003)

`secret_redaction.py` is now the shared source for:

- `SECRET_PATTERNS`
- `redact_text()`
- `redact_value()`

Sink coverage:

| Sink | Current behavior |
|---|---|
| `trace_output_preview.output_preview_text()` | extracts readable result text, redacts it, truncates it, logs only redacted preview text. |
| `claude_trace_store` | imports shared patterns/redaction; args/results are redacted before preview/hash. |
| `hermes_trace_store` | redacts args, results, and output-guard reasons at the sink before preview/hash/store. |
| `audit.py` | redacts action/reason/human_reason/metadata before audit DB insertion and Langfuse emission. |
| `server.py` | redacts and HTML-escapes stored values before dashboard rendering. |
| `canonical_log.py` / `canonical_log.rs` | both Python and Rust apply byte-equivalent redaction to `input` previews and `out` values while preserving `input_id` on the original canonical input. |

Canonical-log choice: redaction is implemented in both Python and Rust rather than skipped in equivalence mode. `make equivalence` remains the parity gate and reports `MISMATCH 0`.

## GAP-APIKEY-004 known residual: shape probes / char-by-char exfiltration

A full secret redactor can reliably remove complete key-shaped values and configured canaries, but it cannot prove that arbitrary small substrings such as `first=sk-TES last=... len=14` are secret fragments without high false positives. A determined agent that can read a secret source can exfiltrate one character, length bit, or checksum bit at a time and stay below normal full-secret pattern thresholds.

This residual is largely neutralized by GAP-APIKEY-005 because provider keys are no longer in the supervised agent's process environment. Remaining exposure depends on other readable secret sources (for example, an operator-mounted `.env` file, unrestricted filesystem read capability, or same-user access to an owner-only Stage 3 key file in the in-process Hermes MVP path). Future hardening should route all Stage 3 calls through a separate daemon/IPC boundary or enforce a kernel/container read boundary that prevents the agent from opening secret files at all.

The red-team shape-probe test stays `xfail` because fully solving this requires capability separation, not just redaction.

## Automated red-team suite

`tests/security/test_apikey_exfiltration.py` now gates:

- T1: `.env`/read preview path redacts full provider-key sentinels.
- T2: shell/env dump output is detected and not persisted raw in Hermes traces.
- T3: output guard flags full sentinels.
- T4: Claude trace store, Hermes trace store, trace preview, and canonical log redact full sentinels.
- GAP-005: launched agent env does not contain provider-key sentinels, including custom `ASF_SCRUB_ENV_VARS`; Stage 3 can still load OpenRouter auth from a chmod-600 owner-only file after env scrubbing.
- T5: shape probe remains xfail for GAP-APIKEY-004.

Run target:

```bash
make security-apikeys
```
