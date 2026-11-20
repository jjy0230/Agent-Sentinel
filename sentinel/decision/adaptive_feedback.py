"""Online Adaptive Feedback Tuner for Prior Calibration.

Dynamically updates the background prior matrix p0 when a human approves
a grey-zone operation (confirmed=True) using Exponential Moving Average (EMA).
Enables the gateway to adapt to a user or team's specific trusted development workflows.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional
from sentinel.decision.prior_calibrator import PriorCalibrator

logger = logging.getLogger(__name__)


class AdaptiveFeedbackTuner:
    """Online EMA adapter for personalized threshold and prior calibration."""

    def __init__(
        self,
        calibrator: Optional[PriorCalibrator] = None,
        learning_rate: float = 0.05,
    ) -> None:
        self.calibrator = calibrator or PriorCalibrator()
        self.learning_rate = learning_rate

    def record_human_approval(self, raw_command: str) -> Dict[str, float]:
        """Update prior vector when human explicitly confirms execution."""
        current_p0 = self.calibrator.prior_vector

        # When human approves, slightly boost ALLOW prior baseline to reduce repetitive prompts
        # ALLOW adjustment delta: +0.10, BLOCK: -0.05, CONFIRM: -0.05
        deltas = {
            "ALLOW": 0.10,
            "BLOCK": -0.05,
            "REQUIRE_HUMAN_CONFIRM": -0.05,
        }

        updated_p0: Dict[str, float] = {}
        for opt in ["ALLOW", "BLOCK", "REQUIRE_HUMAN_CONFIRM"]:
            old_val = current_p0.get(opt, 0.0)
            delta = deltas.get(opt, 0.0)
            # EMA formula: p_new = (1 - eta) * p_old + eta * (p_old + delta)
            new_val = old_val + (self.learning_rate * delta)
            updated_p0[opt] = round(new_val, 4)

        logger.info(
            "Adaptive feedback applied for approved command '%s'. Prior adjusted: %s",
            raw_command[:30],
            updated_p0,
        )
        self.calibrator.save(updated_p0, model_name="adaptive-online")
        return updated_p0
