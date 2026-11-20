"""Tests for PriorCalibrator and offline prior offset subtraction."""

import pytest
from sentinel.decision.prior_calibrator import PriorCalibrator


def test_prior_calibrator_loading() -> None:
    calibrator = PriorCalibrator()
    prior = calibrator.prior_vector

    assert isinstance(prior, dict)
    assert "ALLOW" in prior
    assert "BLOCK" in prior
    assert "REQUIRE_HUMAN_CONFIRM" in prior


def test_prior_calibrator_save_and_load(tmp_path) -> None:
    test_file = tmp_path / "test_prior.json"
    calibrator = PriorCalibrator(prior_file=test_file)

    dummy_logits = {"ALLOW": 0.5, "BLOCK": -0.5, "REQUIRE_HUMAN_CONFIRM": 0.0}
    calibrator.save(dummy_logits, "test-model")

    new_calibrator = PriorCalibrator(prior_file=test_file)
    assert new_calibrator.prior_vector == dummy_logits
