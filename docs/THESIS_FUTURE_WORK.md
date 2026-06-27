# Thesis Future Work Notes

## API-key fragment / shape-probe residual

GAP-APIKEY-004 remains a fundamental residual for any sink-only redaction layer. Full secret values and configured canaries can be detected and redacted, but a malicious or compromised agent that can read a secret source can leak one character, length bit, prefix/suffix fragment, checksum bit, or timing/shape signal at a time without emitting a complete key-shaped token.

The practical mitigation is capability separation rather than more regexes: provider keys must be removed from the supervised agent's environment and from all agent-readable files, and Stage 3 provider authentication should run in a separate daemon/IPC boundary or inside a host/container policy that prevents the agent process from opening secret material. GAP-APIKEY-005 implements the highest-impact step by scrubbing inherited provider keys from the agent environment; future work should complete the same boundary for all in-process MVP paths and file-read capabilities.
