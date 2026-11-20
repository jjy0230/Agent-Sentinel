"""Dual-Path Security Gateway Orchestrator.

Combines L1 fast heuristic filter, Symbolic Taint variable resolution,
Safe Command Rewriting (Soft-Delete), and L2 AnyJev/Native calibrated semantic inference
to enforce terminal safety under a strict 35ms latency ceiling.
"""

import time
from typing import Optional
from sentinel.config.project_config import ProjectConfig
from sentinel.core.ast_pruner import ASTPruner
from sentinel.core.rules_engine import RulesEngine
from sentinel.core.symbolic_taint import SymbolicTaintAnalyzer
from sentinel.decision.adaptive_feedback import AdaptiveFeedbackTuner
from sentinel.decision.base import BaseDecisionEngine
from sentinel.decision.mock_engine import MockDecisionEngine
from sentinel.models import ActionEnum, CommandContext, EvaluationResult, RiskLevel, SecurityVerdict
from sentinel.rewriter.safe_rewriter import SafeCommandRewriter


class DualPathGateway:
    """The core evaluation pipeline for Agent-Sentinel."""

    def __init__(
        self,
        decision_engine: Optional[BaseDecisionEngine] = None,
        allow_threshold: float = 0.90,
        block_threshold: float = 0.10,
        ast_budget_chars: int = 1200,
        enable_taint_analysis: bool = True,
        enable_auto_rewrite: bool = True,
    ) -> None:
        self.rules_engine = RulesEngine()
        self.ast_pruner = ASTPruner(token_budget_chars=ast_budget_chars)
        self.taint_analyzer = SymbolicTaintAnalyzer() if enable_taint_analysis else None
        self.decision_engine = decision_engine or MockDecisionEngine()
        self.feedback_tuner = AdaptiveFeedbackTuner()
        self.project_config = ProjectConfig.load()
        self.enable_auto_rewrite = enable_auto_rewrite and self.project_config.auto_trash
        self.allow_threshold = allow_threshold
        self.block_threshold = block_threshold

    def evaluate(self, ctx: CommandContext) -> EvaluationResult:
        """Execute end-to-end multi-tier security inspection."""
        t0 = time.perf_counter_ns()

        # Step 0: Check Project-scoped whitelist prefixes
        cmd_lower = ctx.raw_command.strip().lower()
        if any(cmd_lower.startswith(p.lower()) for p in self.project_config.allowed_prefixes):
            t1 = time.perf_counter_ns()
            return EvaluationResult(
                action=ActionEnum.ALLOW,
                risk_level=RiskLevel.LOW,
                verdict=SecurityVerdict(p_allow=0.99),
                reasons=[f"Project Config Whitelist: Matched preset '{self.project_config.preset}'"],
                latency_ms=round((t1 - t0) / 1_000_000, 3),
                evaluator_tier="L1_PROJECT_CONFIG",
                context=ctx,
            )

        # Step 1: L1 Fast-path Filter (< 0.05ms)
        l1_result = self.rules_engine.evaluate(ctx)
        if l1_result is not None:
            t1 = time.perf_counter_ns()
            l1_result.latency_ms = round((t1 - t0) / 1_000_000, 3)
            return l1_result

        # Step 1.5: Smart Auto-Rewrite (Soft-Delete) for local workspace targets
        sanitized_cmd = None
        if self.enable_auto_rewrite:
            rewriter = SafeCommandRewriter(workspace_path=ctx.workspace_path)
            rewrite_res = rewriter.rewrite(ctx.raw_command)
            if rewrite_res.is_rewritten:
                t1 = time.perf_counter_ns()
                return EvaluationResult(
                    action=ActionEnum.ALLOW,
                    risk_level=RiskLevel.LOW,
                    verdict=SecurityVerdict(p_allow=0.95, is_destructive=False),
                    reasons=[rewrite_res.reason or "Safely rewritten to soft-delete"],
                    latency_ms=round((t1 - t0) / 1_000_000, 3),
                    evaluator_tier="L1_SAFE_REWRITER",
                    context=ctx,
                )

        # Step 2: Symbolic Taint Analysis & Variable Propagation (< 0.1ms)
        target_command = ctx.raw_command
        taint_warnings = []
        is_tainted_exfil = False
        is_tainted_destr = False

        if self.taint_analyzer:
            taint_rep = self.taint_analyzer.analyze(ctx.raw_command)
            taint_warnings = taint_rep.propagated_warnings
            is_tainted_exfil = taint_rep.is_tainted_exfiltration
            is_tainted_destr = taint_rep.is_tainted_destruction

            # Use reconstructed de-obfuscated command for deeper AST inspection
            if taint_rep.resolved_commands:
                target_command = " ; ".join(taint_rep.resolved_commands)

        # Step 3: AST Pruning & Obfuscation Detection (< 1ms)
        analysis = self.ast_pruner.analyze(target_command)
        analysis.warnings.extend(taint_warnings)
        if self.taint_analyzer and taint_rep.is_spliced_obfuscation:
            analysis.is_obfuscated = True

        # Step 4: L2 Deep Semantic Evaluation (AnyJev / Native / Mock Engine)
        verdict = self.decision_engine.evaluate(ctx, analysis)

        # Merge Taint violations directly into verdict
        if is_tainted_exfil:
            verdict.is_exfiltration = True
            verdict.p_block = max(verdict.p_block, 0.95)
            verdict.p_allow = min(verdict.p_allow, 0.01)

        if is_tainted_destr:
            verdict.is_destructive = True
            verdict.p_block = max(verdict.p_block, 0.90)
            verdict.p_allow = min(verdict.p_allow, 0.05)

        # Step 5: Decision Routing & Threshold Logic
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

    def record_human_approval(self, raw_command: str) -> None:
        """Incorporate human approval into adaptive prior tuning."""
        self.feedback_tuner.record_human_approval(raw_command)
