"""Process Ancestry and Subprocess Execution Tracer.

Inspects command execution inside wrapper runtimes (e.g. python -c "import os; os.system(...)")
to prevent bypasses where an AI agent attempts to spawn subshells through non-bash languages.
"""

import os
import re
import shlex
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class TracedCommand:
    """Extracted command payload from a process invocation."""
    original_argv: List[str]
    extracted_inner_command: Optional[str]
    runtime_type: str  # 'direct', 'python', 'node', 'ruby', 'perl'
    is_nested_subshell: bool


class ProcessTracer:
    """Recursively unfolds nested code payloads inside script runtimes."""

    # Patterns matching inline system invocations inside scripts
    _RE_INLINE_EXEC = re.compile(
        r"""(?:os\.system|subprocess\.(?:run|Popen|call)|exec|system|`)\s*\(\s*["']([^"']+)["']""",
        re.IGNORECASE
    )

    def trace_argv(self, argv: List[str]) -> TracedCommand:
        """Inspect process arguments and uncover wrapped inner shell commands."""
        if not argv:
            return TracedCommand(
                original_argv=[],
                extracted_inner_command=None,
                runtime_type="empty",
                is_nested_subshell=False,
            )

        binary = os.path.basename(argv[0]).lower()

        # 1. Direct Bash / Sh invocations: e.g. bash -c "cmd"
        if binary in ["bash", "sh", "zsh", "dash"]:
            for idx, arg in enumerate(argv):
                if arg == "-c" and idx + 1 < len(argv):
                    return TracedCommand(
                        original_argv=argv,
                        extracted_inner_command=argv[idx + 1],
                        runtime_type="shell",
                        is_nested_subshell=True,
                    )

        # 2. Python inline code: python -c "import os; os.system('...')"
        elif "python" in binary:
            for idx, arg in enumerate(argv):
                if arg in ["-c", "--command"] and idx + 1 < len(argv):
                    code_snippet = argv[idx + 1]
                    match = self._RE_INLINE_EXEC.search(code_snippet)
                    if match:
                        return TracedCommand(
                            original_argv=argv,
                            extracted_inner_command=match.group(1),
                            runtime_type="python",
                            is_nested_subshell=True,
                        )

        # 3. Node.js inline code: node -e "require('child_process').execSync('...')"
        elif binary in ["node", "nodejs"]:
            for idx, arg in enumerate(argv):
                if arg in ["-e", "--eval"] and idx + 1 < len(argv):
                    code_snippet = argv[idx + 1]
                    match = re.search(r"""(?:execSync|exec|spawnSync)\s*\(\s*["']([^"']+)["']""", code_snippet)
                    if match:
                        return TracedCommand(
                            original_argv=argv,
                            extracted_inner_command=match.group(1),
                            runtime_type="node",
                            is_nested_subshell=True,
                        )

        return TracedCommand(
            original_argv=argv,
            extracted_inner_command=" ".join(argv),
            runtime_type="direct",
            is_nested_subshell=False,
        )
