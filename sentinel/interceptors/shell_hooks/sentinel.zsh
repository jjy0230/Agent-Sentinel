#!/usr/bin/env zsh
# Agent-Sentinel interactive Zsh preexec hook

autoload -Uz add-zsh-hook

sentinel_zsh_preexec() {
    local cmd="$1"
    [ -z "$cmd" ] && return 0

    if ! sentinel check "$cmd" --silent; then
        echo "[AGENT-SENTINEL] Command execution aborted by policy." >&2
        return 1
    fi
}

add-zsh-hook preexec sentinel_zsh_preexec
