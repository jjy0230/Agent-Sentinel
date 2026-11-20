"""Abstract Base Class for Sentinel Decision Engines."""

from abc import ABC, abstractmethod
from typing import Optional
from sentinel.core.ast_pruner import PrunedAnalysis
from sentinel.models import CommandContext, SecurityVerdict


class BaseDecisionEngine(ABC):
    """Abstract interface for L2 deep semantic decision engines."""

    @abstractmethod
    def evaluate(self, ctx: CommandContext, analysis: PrunedAnalysis) -> SecurityVerdict:
        """Run calibrated inference over the command context and pruned AST.

        Args:
            ctx: Command execution context (command, intent, workspace, etc.)
            analysis: Pruned script analysis with detected signals

        Returns:
            SecurityVerdict with calibrated probabilities and hazard flags
        """
        pass

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Human-readable identifier of the decision engine."""
        pass
