#!/usr/bin/env bash
# Agent-Sentinel interactive Bash preexec hook

if [ -z "$AGENT_SENTINEL_LOADED" ]; then
    export AGENT_SENTINEL_LOADED=1

    sentinel_preexec() {
        local cmd="$1"
        # Skip empty
        [ -z "$cmd" ] && return 0

        # Invoke fast sentinel check CLI
        if ! sentinel check "$cmd" --silent; then
            echo "[AGENT-SENTINEL] Command execution aborted by policy." >&2
            return 1
        fi
    }

    # Bind preexec using bash trap if available
    trap 'sentinel_preexec "$BASH_COMMAND"' DEBUG
fi
