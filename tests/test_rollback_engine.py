"""Tests for RollbackEngine and History Journaling."""

import pytest
from pathlib import Path
from sentinel.snapshot.rollback_engine import RollbackEngine


def test_history_logging(tmp_path: Path) -> None:
    engine = RollbackEngine(workspace_path=str(tmp_path))

    snapshot_id = engine.create_snapshot("npm run build", agent="test-agent")
    assert snapshot_id is not None

    history = engine.list_history(limit=5)
    assert len(history) == 1
    assert history[0].command == "npm run build"
    assert history[0].agent == "test-agent"


def test_undo_empty_history(tmp_path: Path) -> None:
    engine = RollbackEngine(workspace_path=str(tmp_path))
    success, msg = engine.undo_last()
    assert success is False
    assert "No command history" in msg
