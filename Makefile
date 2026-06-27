
.PHONY: equivalence security-apikeys
equivalence:
	mkdir -p tests/equivalence/out
	python scripts/equivalence/run_py.py
	cd asf_rust_daemon && cargo run --bin asf-canonical -- ../tests/equivalence/corpus.jsonl ../tests/equivalence/out
	python scripts/equivalence/diff_canonical.py

security-apikeys:
	python -m pytest tests/security/test_apikey_exfiltration.py
