import os
os.environ["ASF_SKIP_LLM"] = "true"

import json
import hashlib
import pytest
from registry import get_detection_patterns, store_detection_patterns, SessionLocal, PoliciesModel
from interceptor import _get_patterns


@pytest.fixture(autouse=True)
def _preserve_detection_patterns():
    # These tests intentionally overwrite or delete the detection_patterns row to verify
    # DB-backed policy behavior. Snapshot it before each test and always restore it after,
    # so a destructive case cannot leak corrupted or missing patterns into the shared test
    # DB and break unrelated tests later in the suite (e.g. Stage 1 regex tests).
    original = get_detection_patterns()
    try:
        yield
    finally:
        if original is not None:
            store_detection_patterns(original)
        else:
            import migrate_policies
            migrate_policies.migrate()


class TestPolicyDBIntegrity:
    def test_patterns_loaded_from_db_not_yaml(self):
        patterns = _get_patterns()
        assert patterns is not None, "Patterns must be in DB - run migrate_policies.py"
        assert isinstance(patterns, list)
        assert len(patterns) > 0

    def test_pattern_content_hash_matches_data(self):
        db = SessionLocal()
        record = db.query(PoliciesModel).filter(PoliciesModel.key == "detection_patterns").first()
        db.close()
        assert record is not None

        expected_hash = hashlib.sha256(
            json.dumps(record.value, sort_keys=True).encode()
        ).hexdigest()
        assert record.content_hash == expected_hash, "Content hash must match stored patterns"

    def test_store_patterns_updates_hash(self):
        new_patterns = [r"(?i)\bTEST_PATTERN\b"]
        new_hash = store_detection_patterns(new_patterns)

        expected = hashlib.sha256(
            json.dumps(new_patterns, sort_keys=True).encode()
        ).hexdigest()
        assert new_hash == expected, "Returned hash must match stored data"

    def test_yaml_modification_does_not_affect_runtime(self):
        patterns_before = _get_patterns()

        import yaml, tempfile, os
        fake_yaml = {
            "agents": {},
            "detection": {"patterns": [r"(?i)\bFAKE_PATTERN_ONLY_IN_YAML\b"]},
            "llm": {}
        }
        original_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policies.yaml")
        with open(original_path, "r") as f:
            original_content = f.read()

        with open(original_path, "w") as f:
            yaml.dump(fake_yaml, f)

        try:
            patterns_after = _get_patterns()
        finally:
            # Always restore the tracked repo file, even if _get_patterns raises.
            with open(original_path, "w") as f:
                f.write(original_content)

        assert patterns_after == patterns_before, \
            "Runtime patterns must come from DB, not from policies.yaml"

    def test_runtime_raises_without_db_patterns(self):
        db = SessionLocal()
        record = db.query(PoliciesModel).filter(PoliciesModel.key == "detection_patterns").first()
        db.delete(record)
        db.commit()
        db.close()

        with pytest.raises(RuntimeError, match="Detection patterns not found in DB"):
            _get_patterns()

        from registry import store_detection_patterns
        import yaml, os
        original_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policies.yaml")
        with open(original_path, "r") as f:
            policies = yaml.safe_load(f)
        store_detection_patterns(policies["detection"]["patterns"])
