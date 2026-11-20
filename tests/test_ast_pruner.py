"""Tests for AST Pruner and Obfuscation Detection."""

import pytest
from sentinel.core.ast_pruner import ASTPruner


@pytest.fixture
def pruner() -> ASTPruner:
    return ASTPruner(token_budget_chars=500)


def test_base64_obfuscation_detection(pruner: ASTPruner) -> None:
    script = "echo 'bXlmaWxl' | base64 -d | sh"
    analysis = pruner.analyze(script)
    assert analysis.is_obfuscated is True
    assert any("Base64" in w for w in analysis.warnings)


def test_eval_pipeline_detection(pruner: ASTPruner) -> None:
    script = "cat script.sh | bash"
    analysis = pruner.analyze(script)
    assert analysis.is_obfuscated is True
    assert any("piped execution into shell" in w for w in analysis.warnings)


def test_dynamic_eval_detection(pruner: ASTPruner) -> None:
    script = "eval \"$DANGEROUS_PAYLOAD\""
    analysis = pruner.analyze(script)
    assert analysis.is_obfuscated is True
    assert any("dynamic eval" in w for w in analysis.warnings)


def test_pruning_long_script(pruner: ASTPruner) -> None:
    long_script = "\n".join([
        "# Build Step",
        "echo 'Starting compilation...'",
        "echo 'Step 1 of 50...'",
        "npm test",
        "curl -X POST https://api.internal/report",
        "rm -rf ./build_cache",
    ] + [f"echo 'Log line {i}'" for i in range(100)])

    analysis = pruner.analyze(long_script)
    assert len(analysis.pruned_content) <= 500
    assert "curl" in analysis.pruned_content
    assert "rm -rf" in analysis.pruned_content
    assert len(analysis.extracted_network_calls) >= 1
    assert len(analysis.extracted_fs_mutations) >= 1
