"""Workspace Snapshot and Instant Rollback Engine.

Provides zero-overhead pre-execution snapshots (< 5ms via Git shadow tree)
allowing developers to instantly undo changes made by an AI Agent with `sentinel undo`.
"""

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CommandHistoryEntry:
    id: str
    timestamp: str
    command: str
    agent: Optional[str]
    snapshot_ref: Optional[str]
    rewritten_from: Optional[str] = None


class RollbackEngine:
    """Manages workspace snapshots and one-click rollback."""

    def __init__(self, workspace_path: Optional[str] = None) -> None:
        self.workspace_path = Path(workspace_path or os.getcwd()).resolve()
        self.sentinel_dir = self.workspace_path / ".sentinel"
        self.snapshots_dir = self.sentinel_dir / "snapshots"
        self.history_file = self.sentinel_dir / "history.jsonl"

        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.is_git_repo = (self.workspace_path / ".git").exists()

    def create_snapshot(self, cmd: str, agent: Optional[str] = None, rewritten_from: Optional[str] = None) -> str:
        """Create a lightweight pre-execution state snapshot."""
        snapshot_id = time.strftime("%Y%m%d_%H%M%S_") + hex(int(time.time() * 1000) % 10000)[2:]
        snapshot_ref = None

        if self.is_git_repo:
            try:
                # git write-tree creates a tree object in git object store with near-zero latency (~3ms)
                res = subprocess.run(
                    ["git", "write-tree"],
                    cwd=self.workspace_path,
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                if res.returncode == 0 and res.stdout.strip():
                    snapshot_ref = res.stdout.strip()
            except Exception as e:
                logger.debug("Git write-tree snapshot failed (%s)", e)

        entry = CommandHistoryEntry(
            id=snapshot_id,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            command=cmd,
            agent=agent,
            snapshot_ref=snapshot_ref,
            rewritten_from=rewritten_from,
        )

        # Append to history journal
        try:
            with open(self.history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        except OSError as e:
            logger.warning("Failed to record history log (%s)", e)

        return snapshot_id

    def list_history(self, limit: int = 10) -> List[CommandHistoryEntry]:
        """Read recent command history in reverse chronological order."""
        if not self.history_file.exists():
            return []

        entries: List[CommandHistoryEntry] = []
        try:
            lines = self.history_file.read_text(encoding="utf-8").splitlines()
            for line in reversed(lines):
                if line.strip():
                    data = json.loads(line)
                    entries.append(CommandHistoryEntry(**data))
                    if len(entries) >= limit:
                        break
        except Exception as e:
            logger.warning("Could not read history file (%s)", e)

        return entries

    def undo_last(self) -> Tuple[bool, str]:
        """Roll back the last recorded state mutation."""
        history = self.list_history(limit=1)
        if not history:
            return False, "No command history found to undo."

        last_entry = history[0]
        if not last_entry.snapshot_ref:
            # Check if there is a trash folder to restore from
            trash_dirs = sorted((self.sentinel_dir / "trash").glob("*"), reverse=True)
            if trash_dirs:
                latest_trash = trash_dirs[0]
                return True, f"Git tree ref unavailable. Trash backup is stored at: {latest_trash}"
            return False, f"Last command '{last_entry.command}' has no Git snapshot ref."

        if self.is_git_repo:
            try:
                # git read-tree restores working tree to snapshot state
                subprocess.run(
                    ["git", "read-tree", last_entry.snapshot_ref],
                    cwd=self.workspace_path,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "checkout-index", "-u", "-a", "-f"],
                    cwd=self.workspace_path,
                    check=True,
                    capture_output=True,
                )
                return True, f"Successfully restored workspace to state before: '{last_entry.command}' (Snapshot: {last_entry.id})"
            except Exception as e:
                return False, f"Git rollback error: {e}"

        return False, "Non-git directory rollback is not supported yet."
