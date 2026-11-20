"""Tests for SafeCommandRewriter and Soft-Delete Engine."""

import pytest
from pathlib import Path
from sentinel.rewriter.safe_rewriter import SafeCommandRewriter


def test_rewrite_workspace_rm_rf(tmp_path: Path) -> None:
    rewriter = SafeCommandRewriter(workspace_path=str(tmp_path))
    cmd = "rm -rf dist/"
    res = rewriter.rewrite(cmd)

    assert res.is_rewritten is True
    assert ".sentinel/trash" in res.rewritten_command or "Move-Item" in res.rewritten_command
    assert res.backup_path is not None


def test_do_not_rewrite_catastrophic_root(tmp_path: Path) -> None:
    rewriter = SafeCommandRewriter(workspace_path=str(tmp_path))
    catastrophic_cmds = [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf /etc",
    ]
    for cmd in catastrophic_cmds:
        res = rewriter.rewrite(cmd)
        assert res.is_rewritten is False, f"Catastrophic {cmd} should never be rewritten into safe move"


def test_do_not_rewrite_non_rm(tmp_path: Path) -> None:
    rewriter = SafeCommandRewriter(workspace_path=str(tmp_path))
    cmd = "git status"
    res = rewriter.rewrite(cmd)
    assert res.is_rewritten is False
    assert res.rewritten_command == cmd
