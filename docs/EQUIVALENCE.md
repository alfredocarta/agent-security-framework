# Canonical logging equivalence harness

Set `ASF_CANONICAL_LOG` to append one canonical JSON line per instrumented deterministic function call. The harness runs the same corpus through Python and Rust ports, normalizes outputs, then diffs records by `(op, input_id)`. Stage 2 sklearn and Stage 3 LLM/ONNX are outside the Rust equivalence boundary; any boundary mismatch is reported rather than hidden.

Run:

```sh
make equivalence
```

Read the report:

- MATCH: same canonical `out` for Python and Rust.
- MISMATCH: same op/input but field-level output differences.
- ONLY_IN_PY / ONLY_IN_RUST: one implementation failed to emit a canonical line.
- CRITICAL_PATTERN_DIVERGENCE: Python `re` and Rust `regex` compile or match-set differences over the corpus.

Instrumentation is additive and gated by `ASF_CANONICAL_LOG`; unset means no log writes.
