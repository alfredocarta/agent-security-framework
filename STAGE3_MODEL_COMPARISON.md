# Stage 3 Model Comparison

Benchmark date: 2026-05-19

Scope: isolated Stage 3-style semantic classification on compact T01-T09
adversarial and benign payloads from `agent-security-evaluation`. This is not
the full ASF pipeline result; it measures whether a candidate can replace the
Gemma 2B semantic fallback by itself.

Decision threshold:

- candidate replacement if `detection_rate >= 0.95`
- `fp_rate <= 0.05`
- average latency `< 100ms`

| Model | Size | Avg latency | Detection rate | FP rate | Notes |
|---|---:|---:|---:|---:|---|
| Gemma 2B via Ollama (`gemma2:2b`) | 1.6GB | 289.5ms | 1.0000 | 0.3333 | Current Stage 3 fallback. Strong recall on this compact set, but over-blocks benign tool-security cases when used standalone. |
| Qwen2.5 0.5B Instruct via Ollama (`qwen2.5:0.5b`) | 397MB local Ollama artifact | 146.3ms | 1.0000 | 0.7778 | Pulled and benchmarked locally. Faster than Gemma, but too many false positives and still above the 100ms target. |
| ProtectAI `deberta-v3-base-prompt-injection-v2` | ~400MB | 92.6ms | 0.3333 | 0.3333 | Downloaded from HuggingFace and benchmarked. Fast, Apache 2.0, but misses non-prompt-injection ASF threat classes such as unauthorized tools, SQL intent, delegation, and degraded-state risk. |
| Meta `Llama-Prompt-Guard-2-22M` | 22M parameters / ~90MB class | Not benchmarked | Not benchmarked | Not benchmarked | HuggingFace model exists but access is gated; unauthenticated download returned `401 Unauthorized`. Promising latency profile in model card, but requires license/access approval before local evaluation. |
| `tihilya/modernbert-base-prompt-injection-detection` | ModernBERT-base class | 61.7ms | 0.4444 | 0.0000 | Downloaded from HuggingFace and benchmarked as the available ModernBERT prompt-injection candidate. Excellent FP behavior, but low recall on broad ASF tool-security threats. |

## Availability checks

- Ollama initially had only `gemma2:2b`; `qwen2.5:0.5b` was pulled successfully.
- ProtectAI DeBERTa v2 downloaded and ran through Transformers.
- Meta Prompt Guard 22M is available on HuggingFace but gated; no local benchmark
  without an authenticated token.
- The ModernBERT candidate `tihilya/modernbert-base-prompt-injection-detection`
  downloaded and ran through Transformers.

## Recommendation

Do not replace Gemma 2B Stage 3 with any tested candidate yet.

Qwen2.5 0.5B has adequate recall but unacceptable false positives and latency
above the target. ProtectAI and ModernBERT are useful specialist classifiers for
prompt injection, but Stage 3 currently adjudicates broader agent-security
semantics: unauthorized tool use, SQL injection, delegation abuse, audit
tampering, persistence after suspension, and fail-closed behavior. Those
specialist models miss too many of those classes when used as the sole Stage 3
replacement.

Best next step: keep Gemma 2B as Stage 3 for now, and consider adding a small
expert classifier only as a pre-filter or ensemble vote. Meta Prompt Guard 22M
is worth benchmarking after HuggingFace access is approved because it is the only
candidate with a plausible size/latency profile for the stated replacement bar.

## Sources

- Qwen2.5 0.5B availability: https://ollama.com/library/qwen2.5
- Qwen2.5 0.5B GGUF / Ollama variant: https://ollama.com/gbenson/qwen2.5-0.5b-instruct
- ProtectAI model card: https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2
- Meta Prompt Guard 22M model card: https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M
- ModernBERT candidate: https://huggingface.co/tihilya/modernbert-base-prompt-injection-detection
