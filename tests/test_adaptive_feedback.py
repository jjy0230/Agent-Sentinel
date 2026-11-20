"""Tests for Adaptive Feedback Tuner."""

import pytest
from sentinel.decision.adaptive_feedback import AdaptiveFeedbackTuner
from sentinel.decision.prior_calibrator import PriorCalibrator


def test_adaptive_feedback_ema_update(tmp_path) -> None:
    test_prior_file = tmp_path / "prior.json"
    calibrator = PriorCalibrator(prior_file=test_prior_file)
    calibrator.save({"ALLOW": 0.0, "BLOCK": 0.0, "REQUIRE_HUMAN_CONFIRM": 0.0}, "test-model")

    tuner = AdaptiveFeedbackTuner(calibrator=calibrator, learning_rate=0.10)

    # User approves a command
    updated_prior = tuner.record_human_approval("custom_internal_tool --sync")

    assert updated_prior["ALLOW"] > 0.0
    assert updated_prior["BLOCK"] < 0.0
    assert updated_prior["REQUIRE_HUMAN_CONFIRM"] < 0.0
