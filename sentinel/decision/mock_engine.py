"""Heuristic Mock Engine for testing and lightweight local evaluation.

Simulates AnyJev's calibrated probabilities without requiring local GPU or model weights.
Uses deterministic hazard scoring mapped onto calibrated Dirichlet-style probability distributions.
"""

import re
from typing import List
from sentinel.core.ast_pruner import PrunedAnalysis
from sentinel.decision.base import BaseDecisionEngine
from sentinel.models import CommandContext, SecurityVerdict


class MockDecisionEngine(BaseDecisionEngine):
    """Deterministic Mock Engine mirroring AnyJev's typed probability distribution."""

    def __init__(self, simulated_latency_ms: float = 0.5) -> None:
        self._simulated_latency = simulated_latency_ms
        self._sensitive_paths_re = re.compile(
            r"(\.ssh/|id_rsa|\.aws/credentials|credentials|\.config/gcloud|\.env|/etc/shadow|/etc/passwd|\.gnupg)",
            re.IGNORECASE,
        )
        self._outbound_net_re = re.compile(
            r"(curl|wget|nc|netcat|socat|ncat|telnet|ssh|scp|sftp)",
            re.IGNORECASE,
        )
        self._destructive_fs_re = re.compile(
            r"\b(rm|mv|dd|shred|truncate|mkfs|fdisk|chown|chmod|iptables|ufw)\b|>|>>",
            re.IGNORECASE,
        )

    @property
    def engine_name(self) -> str:
        return "L2_MOCK_HEURISTIC"

    def evaluate(self, ctx: CommandContext, analysis: PrunedAnalysis) -> SecurityVerdict:
        cmd = ctx.raw_command
        pruned = analysis.pruned_content or cmd

        is_exfiltration = False
        is_destructive = False
        is_privilege_escalation = False

        has_sensitive_path = bool(self._sensitive_paths_re.search(pruned))
        has_network = bool(self._outbound_net_re.search(pruned)) or bool(analysis.extracted_network_calls)
        has_destructive_op = bool(self._destructive_fs_re.search(pruned)) or bool(analysis.extracted_fs_mutations)
        is_obfuscated = analysis.is_obfuscated

        if "sudo " in pruned or "doas " in pruned:
            is_privilege_escalation = True

        # Exfiltration detection: Access sensitive path + Pipe/Network post
        if has_sensitive_path and (has_network or "|" in cmd):
            is_exfiltration = True

        # Destructive detection: Force remove, disk overwrite, unconstrained wildcards
        if has_destructive_op:
            if any(k in pruned for k in ["-rf", "-f", "/dev/", "truncate", ">"]):
                is_destructive = True

        # Remote execution pipeline detection: curl ... | sh, wget ... | bash
        if has_network and any(sh in pruned for sh in ["| sh", "| bash", "|sh", "|bash", "sh -c", "bash -c", "| /bin/bash", "| /bin/sh"]):
            is_destructive = True

        # Calculate calibrated probabilities
        if is_exfiltration or (is_destructive and is_obfuscated):
            # Definite high-threat attack
            p_allow = 0.01
            p_block = 0.95
            p_confirm = 0.04
        elif is_destructive or is_obfuscated:
            # Dangerous or ambiguous obfuscation
            p_allow = 0.05
            p_block = 0.35
            p_confirm = 0.60
        elif is_privilege_escalation or has_sensitive_path or analysis.is_truncated:
            # Grey zone requiring user verification
            p_allow = 0.20
            p_block = 0.15
            p_confirm = 0.65
        else:
            # Standard developer command (e.g. npm install, git push, pytest)
            p_allow = 0.96
            p_block = 0.01
            p_confirm = 0.03

        return SecurityVerdict(
            p_allow=round(p_allow, 4),
            p_block=round(p_block, 4),
            p_confirm=round(p_confirm, 4),
            is_destructive=is_destructive,
            is_exfiltration=is_exfiltration,
            is_obfuscated=is_obfuscated,
            is_privilege_escalation=is_privilege_escalation,
        )
