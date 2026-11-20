"""Dual-Path Security Gateway Orchestrator.

Combines L1 fast heuristic filter and L2 AnyJev calibrated semantic inference
to enforce terminal safety under a strict 35ms latency ceiling.
"""

import time
from typing import Optional
from sentinel.core.ast_pruner import ASTPruner
from sentinel.core.rules_engine import RulesEngine
from sentinel.decision.base import BaseDecisionEngine
from sentinel.decision.mock_engine import MockDecisionEngine
from sentinel.models import ActionEnum, CommandContext, EvaluationResult, RiskLevel, SecurityVerdict


class DualPathGateway:
    """The core evaluation pipeline for Agent-Sentinel."""

    def __init__(
        self,
        decision_engine: Optional[BaseDecisionEngine] = None,
        allow_threshold: float = 0.90,
        block_threshold: float = 0.10,
        ast_budget_chars: int = 1200,
    ) -> None:
        self.rules_engine = RulesEngine()
        self.ast_pruner = ASTPruner(token_budget_chars=ast_budget_chars)
        self.decision_engine = decision_engine or MockDecisionEngine()
        self.allow_threshold = allow_threshold
        self.block_threshold = block_threshold

    def evaluate(self, ctx: CommandContext) -> EvaluationResult:
        """Execute end-to-end multi-tier security inspection."""
        t0 = time.perf_counter_ns()

        # Step 1: L1 Fast-path Filter (< 0.05ms)
        l1_result = self.rules_engine.evaluate(ctx)
        if l1_result is not None:
            t1 = time.perf_counter_ns()
            l1_result.latency_ms = round((t1 - t0) / 1_000_000, 3)
            return l1_result

        # Step 2: AST Pruning & Obfuscation Detection (< 1ms)
        analysis = self.ast_pruner.analyze(ctx.raw_command)

        # Step 3: L2 Deep Semantic Evaluation (AnyJev or Mock Engine)
        verdict = self.decision_engine.evaluate(ctx, analysis)

        # Step 4: Decision Routing & Threshold Logic
        reasons = list(analysis.warnings)
        action: ActionEnum
        risk_level: RiskLevel

        if verdict.is_destructive:
            reasons.append("Identified destructive modification pattern")
        if verdict.is_exfiltration:
            reasons.append("Identified sensitive credential exfiltration attempt")
        if verdict.is_obfuscated:
            reasons.append("Identified shell code obfuscation / dynamic evaluation")

        # Threshold Decision:
        # P(BLOCK) >= 0.10 or confirmed destructive/exfil -> BLOCK
        if verdict.is_exfiltration or (verdict.is_destructive and verdict.p_block >= 0.10) or verdict.p_block >= self.block_threshold:
            action = ActionEnum.BLOCK
            risk_level = RiskLevel.CRITICAL if verdict.is_exfiltration or verdict.is_destructive else RiskLevel.HIGH
            reasons.append(f"Blocked: P(BLOCK)={verdict.p_block:.2f} >= {self.block_threshold:.2f}")

        # P(ALLOW) > 0.90 and safe flags -> ALLOW
        elif verdict.p_allow > self.allow_threshold and not verdict.is_destructive and not verdict.is_exfiltration and not verdict.is_obfuscated:
            action = ActionEnum.ALLOW
            risk_level = RiskLevel.LOW
            reasons.append(f"Allowed: P(ALLOW)={verdict.p_allow:.2f} > {self.allow_threshold:.2f}")

        # Ambiguous Grey Zone -> Prompt Human Confirmation
        else:
            action = ActionEnum.REQUIRE_HUMAN_CONFIRM
            risk_level = RiskLevel.MEDIUM
            reasons.append(f"Ambiguous risk score: P(ALLOW)={verdict.p_allow:.2f}, P(CONFIRM)={verdict.p_confirm:.2f}")

        t1 = time.perf_counter_ns()
        latency_ms = round((t1 - t0) / 1_000_000, 3)

        return EvaluationResult(
            action=action,
            risk_level=risk_level,
            verdict=verdict,
            reasons=reasons,
            latency_ms=latency_ms,
            evaluator_tier=self.decision_engine.engine_name,
            context=ctx,
        )
