"""Smart Command Rewriter and Safe Soft-Delete Engine.

Transparently rewrites destructive commands (such as rm -rf build/) targeting local workspace paths
into non-destructive soft-delete moves (.sentinel/trash/), preventing AI coding agents
from getting stuck on permission errors or hard blocks.
"""

import os
import re
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class RewriteResult:
    """Outcome of command auto-rewriting."""
    is_rewritten: bool
    original_command: str
    rewritten_command: str
    reason: Optional[str] = None
    backup_path: Optional[str] = None


class SafeCommandRewriter:
    """Detects workspace deletion commands and converts them to trash bin moves."""

    ROOT_TARGETS = {"/", "/*", "~", "~/*", "$home", "$home/*", "/etc", "/var", "/usr", "/boot"}

    def __init__(self, workspace_path: Optional[str] = None) -> None:
        self.workspace_path = Path(workspace_path or os.getcwd()).resolve()
        self.trash_dir = self.workspace_path / ".sentinel" / "trash"

    def rewrite(self, cmd: str) -> RewriteResult:
        """Inspect and rewrite dangerous workspace file deletion commands."""
        trimmed = cmd.strip()

        # Check for rm commands: rm -rf <target> or rm -f <target> or rm <target>
        rm_match = re.match(
            r"^\s*rm\s+-(?:r[fF]|f[rR]|rf|f|r)\s+([^\n;|&>]+)$",
            trimmed,
            re.IGNORECASE
        )
        if not rm_match:
            # Also match simple rm <target>
            rm_match = re.match(r"^\s*rm\s+([^\n;|&>]+)$", trimmed, re.IGNORECASE)

        if rm_match:
            raw_targets = rm_match.group(1).strip()
            # Split targets safely
            try:
                targets = shlex.split(raw_targets)
            except ValueError:
                targets = raw_targets.split()

            # Filter out flags if any remained
            file_targets = [t for t in targets if not t.startswith("-")]
            if not file_targets:
                return RewriteResult(False, cmd, cmd)

            # Never rewrite root or catastrophic targets
            for t in file_targets:
                if t.lower() in self.ROOT_TARGETS or t.startswith("/dev/"):
                    return RewriteResult(False, cmd, cmd, reason="Catastrophic target cannot be rewritten")

            # Check if all targets are inside or relative to workspace
            safe_to_rewrite = True
            for t in file_targets:
                target_p = Path(t)
                if target_p.is_absolute():
                    try:
                        target_p.resolve().relative_to(self.workspace_path)
                    except ValueError:
                        safe_to_rewrite = False
                        break

            if safe_to_rewrite:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                trash_subdir = self.trash_dir / timestamp
                trash_str = str(trash_subdir).replace("\\", "/")

                if sys.platform != "win32":
                    moves = [
                        f'mv "{t}" "{trash_str}/"' for t in file_targets
                    ]
                    rewritten = f'mkdir -p "{trash_str}" && ' + " && ".join(moves)
                else:
                    # Windows PowerShell / CMD compatible move
                    moves = [
                        f'Move-Item -Path "{t}" -Destination "{trash_str}" -Force' for t in file_targets
                    ]
                    rewritten = f'powershell -Command "New-Item -ItemType Directory -Force -Path \'{trash_str}\' ; ' + " ; ".join(moves) + '"'

                return RewriteResult(
                    is_rewritten=True,
                    original_command=cmd,
                    rewritten_command=rewritten,
                    reason=f"Safely diverted {len(file_targets)} targets to trash ({trash_subdir.name})",
                    backup_path=str(trash_subdir),
                )

        return RewriteResult(False, cmd, cmd)
