import os
os.environ["ASF_SKIP_LLM"] = "true"

import pytest
from unittest.mock import patch
from interceptor import security_interceptor, BLOCK_THRESHOLD, PASS_THRESHOLD
from tests.conftest import is_blocked, is_allowed, is_hitl

class TestStageThresholds:
    def test_block_threshold_constant(self):
        # policies.yaml sets 0.95; env var ASF_BLOCK_THRESHOLD can override.
        # Test that the loaded value is within the valid calibrated range.
        assert 0.7 <= BLOCK_THRESHOLD <= 1.0, f"Block threshold {BLOCK_THRESHOLD} out of valid range [0.7, 1.0]"

    def test_pass_threshold_constant(self):
        # policies.yaml sets 0.05; env var ASF_PASS_THRESHOLD can override.
        assert 0.0 <= PASS_THRESHOLD <= 0.3, f"Pass threshold {PASS_THRESHOLD} out of valid range [0.0, 0.3]"

    def test_stage2_dangerous_above_block_threshold(self):
        # Derive probabilities from the live thresholds so the tests do not drift when
        # policies.yaml retunes block_threshold/pass_threshold (e.g. 0.85 -> 0.95).
        dangerous = min(BLOCK_THRESHOLD + 0.04, 1.0)
        mock_proba = [[1.0 - dangerous, dangerous]]
        with patch("interceptor._classifier") as mock_clf:
            mock_clf.predict_proba.return_value = mock_proba
            result = security_interceptor("billing_agent", "read_db", "test input")
            assert is_blocked(result), f"dangerous_proba={dangerous:.2f} >= {BLOCK_THRESHOLD} must be BLOCKED"

    def test_stage2_safe_below_pass_threshold(self):
        dangerous = max(PASS_THRESHOLD - 0.02, 0.0)
        mock_proba = [[1.0 - dangerous, dangerous]]
        with patch("interceptor._classifier") as mock_clf:
            mock_clf.predict_proba.return_value = mock_proba
            result = security_interceptor("billing_agent", "read_db", "test input")
            assert is_allowed(result), f"dangerous_proba={dangerous:.2f} <= {PASS_THRESHOLD} must be ALLOWED"

    def test_stage2_uncertain_in_grey_zone_goes_to_stage3(self):
        dangerous = (PASS_THRESHOLD + BLOCK_THRESHOLD) / 2
        mock_proba = [[1.0 - dangerous, dangerous]]
        # A grey-zone Stage 2 verdict now escalates to Stage 2.5 first; disable Stage 2.5
        # so the escalation deterministically reaches the Stage 3 LLM under test instead
        # of being resolved by the DeBERTa gate.
        with patch.dict(os.environ, {"ASF_DISABLE_STAGE25": "true"}):
            with patch("interceptor._classifier") as mock_clf:
                with patch("interceptor._stage3_llm") as mock_llm:
                    mock_clf.predict_proba.return_value = mock_proba
                    mock_llm.return_value = True
                    result = security_interceptor("billing_agent", "read_db", "ambiguous input")
                    mock_llm.assert_called_once()
                    assert is_hitl(result) or is_blocked(result)

    def test_stage2_exact_block_threshold_is_dangerous(self):
        dangerous = BLOCK_THRESHOLD
        mock_proba = [[1.0 - dangerous, dangerous]]
        with patch("interceptor._classifier") as mock_clf:
            mock_clf.predict_proba.return_value = mock_proba
            result = security_interceptor("billing_agent", "read_db", "test input")
            assert is_blocked(result), f"dangerous_proba={dangerous:.2f} == {BLOCK_THRESHOLD} must be BLOCKED"

    def test_stage2_exact_pass_threshold_is_safe(self):
        dangerous = PASS_THRESHOLD
        mock_proba = [[1.0 - dangerous, dangerous]]
        with patch("interceptor._classifier") as mock_clf:
            mock_clf.predict_proba.return_value = mock_proba
            result = security_interceptor("billing_agent", "read_db", "test input")
            assert is_allowed(result), f"dangerous_proba={dangerous:.2f} == {PASS_THRESHOLD} must be ALLOWED"

    def test_stage1_blocks_before_stage2_is_called(self):
        with patch("interceptor._stage2_classifier") as mock_stage2:
            result = security_interceptor("billing_agent", "write_db", "DROP TABLE users")
            mock_stage2.assert_not_called(), "Stage 2 must not be called if Stage 1 blocks"
            assert is_blocked(result)

    def test_stage3_not_called_when_stage2_is_safe(self):
        mock_proba = [[0.95, 0.05]]
        with patch("interceptor._classifier") as mock_clf:
            with patch("interceptor._stage3_llm") as mock_llm:
                mock_clf.predict_proba.return_value = mock_proba
                security_interceptor("billing_agent", "read_db", "safe input")
                mock_llm.assert_not_called(), "Stage 3 must not be called when Stage 2 is SAFE"

    def test_onnx_clear_does_not_bypass_always_stage25(self):
        """ONNX SAFE must not return ALLOW when ASF_ALWAYS_STAGE25=true."""
        with patch.dict(os.environ, {"ASF_ALWAYS_STAGE25": "true", "ASF_SKIP_LLM": "true"}):
            with patch("interceptor._classifier") as mock_clf:
                with patch("stage3_onnx.classify_text", return_value="SAFE"):
                    mock_clf.predict_proba.return_value = [[0.95, 0.05]]  # Stage 2 SAFE
                    from interceptor import hardened_interceptor
                    import registry
                    registry.reinstate_agent("billing_agent")
                    result = hardened_interceptor("billing_agent", "read_db", "safe input")
                    # ONNX said SAFE but Always-Stage25 must still reach DeBERTa
                    # Result may be ALLOW (DeBERTa cleared) or DENY (DeBERTa blocked)
                    # but must NOT be "Cleared by ONNX Prompt Guard"
                    assert result[1] != "Cleared by ONNX Prompt Guard", \
                        "ONNX must not clear input when ASF_ALWAYS_STAGE25=true"

    def test_stage3_not_called_when_stage2_is_dangerous(self):
        mock_proba = [[0.05, 0.95]]
        with patch("interceptor._classifier") as mock_clf:
            with patch("interceptor._stage3_llm") as mock_llm:
                mock_clf.predict_proba.return_value = mock_proba
                security_interceptor("billing_agent", "read_db", "dangerous input")
                mock_llm.assert_not_called(), "Stage 3 must not be called when Stage 2 is DANGEROUS"
