# IP Boundary — ASF

This document defines which components of ASF are considered confidential intellectual
property and which are intentionally visible for auditability.

## Confidential (not for redistribution or publication in full)

- The specific numeric thresholds, weights, and scoring logic inside the Rust Stage 1
  and L1.5 classifiers (src/stage1/ and src/l1_5/ in the Rust crate).
- Any trained model weights or heuristic calibration data, if added in future versions.

## Visible and auditable by design

- The Python pipeline architecture: stage interfaces, call graph, session/agent ID handling.
- The hook enforcement mechanism for Claude Code and Hermes.
- The SQLite schema and audit log format.
- The wrapper entry point (asf-run) and its preflight, daemon, and update logic.
- The LangGraph integration and agent dispatching logic.

## Rationale

Academic evaluators and security reviewers need to inspect the enforcement mechanism to
assess its correctness. Keeping the pipeline visible supports auditability without exposing
the classifier internals that represent the core research contribution.

## Future work

If classifier logic is extracted into a separate private module or distributed as a
compiled artifact, this boundary document should be updated accordingly.
