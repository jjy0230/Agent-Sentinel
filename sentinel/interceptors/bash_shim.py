"""POSIX Bash / Sh Shim Wrapper.

Can be placed in PATH or configured as the agent shell executable.
Intercepts non-interactive subprocess invocations (e.g. bash -c "...")
and evaluates commands before invoking the underlying shell.
"""

import os
import sys
from sentinel.ipc.client import SentinelClient
from sentinel.models import ActionEnum, CommandContext

REAL_BASH_PATH = os.environ.get("REAL_BASH_PATH", "/bin/bash")


def main() -> None:
    args = sys.argv[1:]

    # Check if this is a -c command invocation: e.g. bash -c "command"
    cmd_to_inspect = None
    for idx, arg in enumerate(args):
        if arg == "-c" and idx + 1 < len(args):
            cmd_to_inspect = args[idx + 1]
            break

    if cmd_to_inspect:
        client = SentinelClient()
        ctx = CommandContext(
            raw_command=cmd_to_inspect,
            workspace_path=os.getcwd(),
            caller_agent="bash-shim",
        )
        res = client.check(ctx)

        if res.action == ActionEnum.BLOCK:
            sys.stderr.write(f"\n[AGENT-SENTINEL ALERT] Execution Blocked!\n")
            sys.stderr.write(f"Reasons: {', '.join(res.reasons)}\n")
            sys.stderr.write(f"Risk Level: {res.risk_level.value}\n")
            sys.exit(126)  # Standard command invoked cannot execute exit code

        elif res.action == ActionEnum.REQUIRE_HUMAN_CONFIRM:
            sys.stderr.write(f"\n[AGENT-SENTINEL] Ambiguous command detected:\n")
            sys.stderr.write(f"Command: {cmd_to_inspect}\n")
            sys.stderr.write(f"Reasons: {', '.join(res.reasons)}\n")
            try:
                confirm = input("Allow execution? [y/N]: ").strip().lower()
                if confirm != "y":
                    sys.stderr.write("[AGENT-SENTINEL] Execution aborted by user.\n")
                    sys.exit(130)
            except (EOFError, KeyboardInterrupt):
                sys.stderr.write("\n[AGENT-SENTINEL] Non-interactive confirm aborted.\n")
                sys.exit(130)

    # Exec underlying real bash
    if sys.platform != "win32":
        os.execv(REAL_BASH_PATH, [REAL_BASH_PATH] + args)
    else:
        import subprocess
        proc = subprocess.run([REAL_BASH_PATH] + args)
        sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
