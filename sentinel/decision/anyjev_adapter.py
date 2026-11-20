"""AnyJev Decision Engine Adapter.

Integrates with Nokia Bell Labs / Applied Research AnyJev framework
(https://github.com/nokia-applied-research/AnyJev) to extract typed decisions
and calibrated log-probabilities without open-ended generation.
"""

import logging
import math
from typing import Any, Dict, Optional
from sentinel.core.ast_pruner import PrunedAnalysis
from sentinel.decision.base import BaseDecisionEngine
from sentinel.decision.prior_calibrator import PriorCalibrator
from sentinel.models import CommandContext, SecurityVerdict

logger = logging.getLogger(__name__)


class AnyJevAdapter(BaseDecisionEngine):
    """Production Adapter for Nokia AnyJev Decider / Tacit models."""

    def __init__(
        self,
        model_name_or_path: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
        device: str = "cuda",
        use_tacit: bool = False,
        confidence_threshold: float = 0.90,
        alpha: float = 0.85,
    ) -> None:
        self.model_name_or_path = model_name_or_path
        self.device = device
        self.use_tacit = use_tacit
        self.confidence_threshold = confidence_threshold
        self.alpha = alpha
        self._decider = None
        self._tacit = None
        self._prior_calibrator = PriorCalibrator()

        self._initialize_backend()

    @property
    def engine_name(self) -> str:
        return f"L2_ANYJEV({self.model_name_or_path})"

    def _initialize_backend(self) -> None:
        """Dynamically load AnyJev dependencies."""
        try:
            if self.use_tacit:
                from anyjev import Tacit  # type: ignore
                logger.info("Loading AnyJev Tacit distilled checkpoint: %s", self.model_name_or_path)
                self._tacit = Tacit.from_pretrained(self.model_name_or_path, device=self.device)
            else:
                from anyjev import Decider  # type: ignore
                from anyjev.backends.hf import HFBackend  # type: ignore
                logger.info("Loading AnyJev Decider with HuggingFace backend: %s", self.model_name_or_path)
                self._decider = Decider(HFBackend(self.model_name_or_path, device=self.device))
        except ImportError as exc:
            logger.warning(
                "AnyJev package is not installed or GPU backend unavailable (%s). "
                "To enable production AnyJev, run: pip install 'anyjev[hf]' torch transformers",
                exc,
            )
            self._decider = None
            self._tacit = None

    def evaluate(self, ctx: CommandContext, analysis: PrunedAnalysis) -> SecurityVerdict:
        """Run single forward-pass calibrated inference using AnyJev."""
        if self._decider is None and self._tacit is None:
            raise RuntimeError(
                "AnyJev backend is not initialized. Please install anyjev and provide model weights, "
                "or switch to MockDecisionEngine for zero-dependency local simulation."
            )

        prompt_state = self._build_prompt_state(ctx, analysis)

        if self._tacit is not None:
            return self._evaluate_tacit(prompt_state, analysis)
        else:
            return self._evaluate_decider_single_forward(prompt_state, analysis)

    def _build_prompt_state(self, ctx: CommandContext, analysis: PrunedAnalysis) -> str:
        intent = ctx.agent_intent or "Execute development command"
        workspace = ctx.workspace_path or "Unknown workspace"
        cmd = analysis.pruned_content or ctx.raw_command

        warnings_str = ", ".join(analysis.warnings) if analysis.warnings else "None"

        return (
            f"<|im_start|>system\nYou are an ultra-low-latency terminal security guardrail.<|im_end|>\n"
            f"<|im_start|>user\n"
            f"Agent Goal: {intent}\n"
            f"Workspace Path: {workspace}\n"
            f"Static Warnings: {warnings_str}\n"
            f"Command to Inspect:\n{cmd}\n"
            f"Question: Select action from [ALLOW, BLOCK, REQUIRE_HUMAN_CONFIRM].<|im_end|>\n"
            f"<|im_start|>assistant\nDecision:"
        )

    def _evaluate_tacit(self, prompt_state: str, analysis: PrunedAnalysis) -> SecurityVerdict:
        """Evaluate using distilled single-forward Tacit model."""
        decision = self._tacit.decide(
            state=prompt_state,
            question="What is the safety verdict for this terminal command?",
            options=["ALLOW", "BLOCK", "REQUIRE_HUMAN_CONFIRM"],
        )
        probs = decision.get("probs", {})
        p_allow = probs.get("ALLOW", 0.33)
        p_block = probs.get("BLOCK", 0.33)
        p_confirm = probs.get("REQUIRE_HUMAN_CONFIRM", 0.34)

        is_destr = self._tacit.decide(
            state=prompt_state,
            question="Does this command perform destructive filesystem modifications?",
            options=["YES", "NO"],
        )["probs"].get("YES", 0.0) > 0.5

        is_exfil = self._tacit.decide(
            state=prompt_state,
            question="Does this command leak sensitive credentials or private keys outside?",
            options=["YES", "NO"],
        )["probs"].get("YES", 0.0) > 0.5

        return SecurityVerdict(
            p_allow=float(p_allow),
            p_block=float(p_block),
            p_confirm=float(p_confirm),
            is_destructive=is_destr,
            is_exfiltration=is_exfil,
            is_obfuscated=analysis.is_obfuscated,
        )

    def _evaluate_decider_single_forward(self, prompt_state: str, analysis: PrunedAnalysis) -> SecurityVerdict:
        """Evaluate using single forward pass with offline prior subtraction."""
        from anyjev import Question  # type: ignore

        action_q = Question.choice(
            "What is the safety verdict for this terminal command?",
            ["ALLOW", "BLOCK", "REQUIRE_HUMAN_CONFIRM"],
            name="action",
        )
        action_res = self._decider.decide(prompt_state, action_q)

        # Apply offline prior normalization: logit_calibrated = logit_raw - alpha * p0_logit
        raw_probs = action_res.probs
        p0 = self._prior_calibrator.prior_vector

        # Convert to unnormalized logits and subtract prior
        adj_logits = {}
        for opt in ["ALLOW", "BLOCK", "REQUIRE_HUMAN_CONFIRM"]:
            p = max(raw_probs.get(opt, 1e-4), 1e-6)
            raw_logit = math.log(p)
            adj_logits[opt] = raw_logit - (self.alpha * p0.get(opt, 0.0))

        # Softmax over calibrated logits
        max_logit = max(adj_logits.values())
        exp_vals = {opt: math.exp(val - max_logit) for opt, val in adj_logits.items()}
        sum_exp = sum(exp_vals.values())
        calibrated_probs = {opt: round(val / sum_exp, 4) for opt, val in exp_vals.items()}

        p_allow = calibrated_probs.get("ALLOW", 0.0)
        p_block = calibrated_probs.get("BLOCK", 0.0)
        p_confirm = calibrated_probs.get("REQUIRE_HUMAN_CONFIRM", 0.0)

        # Destructive & exfiltration flags
        destr_q = Question.boolean("Does this command perform destructive filesystem modifications?", name="is_destructive")
        exfil_q = Question.boolean("Does this command leak sensitive credentials or private keys outside?", name="is_exfiltration")

        destr_res = self._decider.decide(prompt_state, destr_q)
        exfil_res = self._decider.decide(prompt_state, exfil_q)

        is_destr = destr_res.probs.get(True, 0.0) > 0.5
        is_exfil = exfil_res.probs.get(True, 0.0) > 0.5

        return SecurityVerdict(
            p_allow=float(p_allow),
            p_block=float(p_block),
            p_confirm=float(p_confirm),
            is_destructive=is_destr,
            is_exfiltration=is_exfil,
            is_obfuscated=analysis.is_obfuscated,
        )
