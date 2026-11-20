"""Tests for Decision Engine interface and adapter contracts."""

import pytest
from sentinel.core.ast_pruner import ASTPruner
from sentinel.decision.base import BaseDecisionEngine
from sentinel.decision.mock_engine import MockDecisionEngine
from sentinel.decision.anyjev_adapter import AnyJevAdapter
from sentinel.models import CommandContext, SecurityVerdict


def test_mock_engine_conformance() -> None:
    engine = MockDecisionEngine()
    assert isinstance(engine, BaseDecisionEngine)

    ctx = CommandContext(raw_command="ls -la")
    analysis = ASTPruner().analyze("ls -la")
    verdict = engine.evaluate(ctx, analysis)

    assert isinstance(verdict, SecurityVerdict)
    assert 0.0 <= verdict.p_allow <= 1.0
    assert 0.0 <= verdict.p_block <= 1.0
    assert 0.0 <= verdict.p_confirm <= 1.0
    assert abs((verdict.p_allow + verdict.p_block + verdict.p_confirm) - 1.0) < 0.05


def test_anyjev_adapter_uninitialized_safety() -> None:
    # AnyJevAdapter without installed weights should raise RuntimeError when evaluated
    adapter = AnyJevAdapter(model_name_or_path="nonexistent-mock-path")
    ctx = CommandContext(raw_command="ls")
    analysis = ASTPruner().analyze("ls")

    with pytest.raises(RuntimeError) as exc_info:
        adapter.evaluate(ctx, analysis)
    assert "AnyJev backend is not initialized" in str(exc_info.value)
