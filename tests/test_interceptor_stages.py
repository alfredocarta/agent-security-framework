import os
os.environ["ASF_SKIP_LLM"] = "true"

import pytest
from unittest.mock import patch
from interceptor import security_interceptor, BLOCK_THRESHOLD, PASS_THRESHOLD
from tests.conftest import is_blocked, is_allowed, is_hitl

class TestStageThresholds:
    def test_block_threshold_constant(self):
        assert BLOCK_THRESHOLD == 0.85, "Block threshold must be 0.85"

    def test_pass_threshold_constant(self):
        assert PASS_THRESHOLD == 0.25, "Pass threshold must be 0.25"

    def test_stage2_dangerous_above_block_threshold(self):
        mock_proba = [[0.10, 0.90]]
        with patch("interceptor._classifier") as mock_clf:
            mock_clf.predict_proba.return_value = mock_proba
            result = security_interceptor("billing_agent", "read_db", "test input")
            assert is_blocked(result), f"dangerous_proba=0.90 >= 0.85 must be BLOCKED"

    def test_stage2_safe_below_pass_threshold(self):
        mock_proba = [[0.95, 0.05]]
        with patch("interceptor._classifier") as mock_clf:
            mock_clf.predict_proba.return_value = mock_proba
            result = security_interceptor("billing_agent", "read_db", "test input")
            assert is_allowed(result), f"dangerous_proba=0.05 <= 0.25 must be ALLOWED"

    def test_stage2_uncertain_in_grey_zone_goes_to_stage3(self):
        mock_proba = [[0.50, 0.50]]
        with patch("interceptor._classifier") as mock_clf:
            with patch("interceptor._stage3_llm") as mock_llm:
                mock_clf.predict_proba.return_value = mock_proba
                mock_llm.return_value = True
                result = security_interceptor("billing_agent", "read_db", "ambiguous input")
                mock_llm.assert_called_once(), "Stage 3 must be invoked when classifier is uncertain"
                assert is_hitl(result) or is_blocked(result)

    def test_stage2_exact_block_threshold_is_dangerous(self):
        mock_proba = [[0.15, 0.85]]
        with patch("interceptor._classifier") as mock_clf:
            mock_clf.predict_proba.return_value = mock_proba
            result = security_interceptor("billing_agent", "read_db", "test input")
            assert is_blocked(result), f"dangerous_proba=0.85 == threshold must be BLOCKED"

    def test_stage2_exact_pass_threshold_is_safe(self):
        mock_proba = [[0.75, 0.25]]
        with patch("interceptor._classifier") as mock_clf:
            mock_clf.predict_proba.return_value = mock_proba
            result = security_interceptor("billing_agent", "read_db", "test input")
            assert is_allowed(result), f"dangerous_proba=0.25 == pass_threshold must be ALLOWED"

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

    def test_stage3_not_called_when_stage2_is_dangerous(self):
        mock_proba = [[0.05, 0.95]]
        with patch("interceptor._classifier") as mock_clf:
            with patch("interceptor._stage3_llm") as mock_llm:
                mock_clf.predict_proba.return_value = mock_proba
                security_interceptor("billing_agent", "read_db", "dangerous input")
                mock_llm.assert_not_called(), "Stage 3 must not be called when Stage 2 is DANGEROUS"
