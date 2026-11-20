"""L1 Deterministic Fast-Path Filter.

Evaluates terminal commands in microseconds (< 0.05ms) using pre-compiled regex
and pattern matching to handle ~80% of deterministic commands (safe queries or obvious attacks)
without waking up the neural inference engine.
"""

import re
from typing import List, Optional, Tuple
from sentinel.models import ActionEnum, CommandContext, EvaluationResult, RiskLevel, SecurityVerdict

# Explicit Safe Read-Only commands (Zero external network, zero destructive writes)
SAFE_COMMAND_PREFIXES = (
    "git status",
    "git diff",
    "git log",
    "git branch",
    "git show",
    "git remote -v",
    "ls ",
    "ls -",
    "dir",
    "pwd",
    "whoami",
    "which ",
    "where ",
    "node -v",
    "node --version",
    "npm -v",
    "npm --version",
    "python --version",
    "python -V",
    "python3 --version",
    "python3 -V",
    "cargo --version",
    "cargo check",
    "go version",
    "rustc --version",
    "date",
    "uptime",
)

# Hard Blacklist - Unrecoverable destructive attacks (Immediate Block)
HARD_BLACKLIST_PATTERNS = [
    (r"rm\s+-(?:r[fF]|f[rR]|rf)\s+(?:/|/\*|~|~/\*|\$HOME|\$HOME/\*)", "Catastrophic filesystem purge"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Fork bomb denial of service"),
    (r"mkfs(?:\.[a-z0-9]+)?\s+/dev/[a-z0-9]+", "Raw filesystem format destruction"),
    (r"dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/[a-z0-9]+", "Raw block device wipe"),
    (r">/dev/sd[a-z0-9]+", "Raw disk redirection destruction"),
    (r"chmod\s+-(?:R|r)\s+777\s+/", "Root privilege degradation"),
    (r"sudo\s+rm\s+-(?:r[fF]|f[rR]|rf)\s+/", "Privileged filesystem deletion"),
]

# Sensitive patterns that MUST trigger L2 deep evaluation or immediate flag
SENSITIVE_TARGETS = [
    r"~?/\.ssh/id_[a-z0-9_]+",
    r"~?/\.aws/credentials",
    r"~?/\.config/gcloud/",
    r"\.env(?:\.[a-zA-Z0-9]+)?$",
    r"id_rsa",
    r"/etc/shadow",
    r"/etc/passwd",
]


class RulesEngine:
    """L1 Rule-Based Fast Filter."""

    def __init__(self) -> None:
        self._blacklist_regexes = [
            (re.compile(pat, re.IGNORECASE), reason) for pat, reason in HARD_BLACKLIST_PATTERNS
        ]
        self._sensitive_target_regexes = [
            re.compile(pat, re.IGNORECASE) for pat in SENSITIVE_TARGETS
        ]

    def evaluate(self, ctx: CommandContext) -> Optional[EvaluationResult]:
        """Evaluate command using fast heuristics.

        Returns:
            EvaluationResult if deterministic match found (ALLOW or BLOCK),
            None if command requires L2 deep semantic inspection.
        """
        cmd = ctx.raw_command.strip()
        if not cmd:
            return EvaluationResult(
                action=ActionEnum.ALLOW,
                risk_level=RiskLevel.LOW,
                verdict=SecurityVerdict(p_allow=1.0),
                reasons=["Empty command"],
                evaluator_tier="L1_FAST_RULE",
                context=ctx,
            )

        # 1. Check Hard Blacklist (Instant BLOCK)
        for pattern, reason in self._blacklist_regexes:
            if pattern.search(cmd):
                return EvaluationResult(
                    action=ActionEnum.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    verdict=SecurityVerdict(
                        p_allow=0.0,
                        p_block=1.0,
                        p_confirm=0.0,
                        is_destructive=True,
                    ),
                    reasons=[f"L1 Hard Blacklist: {reason}"],
                    evaluator_tier="L1_FAST_RULE",
                    context=ctx,
                )

        # 2. Check if command contains obvious sensitive file targets
        for pattern in self._sensitive_target_regexes:
            if pattern.search(cmd):
                # Contains sensitive credentials -> Never fast-allow, escalate to L2
                return None

        # 3. Check if command has pipes, network invocations, or subshells
        # If it does, it's dynamic and must be escalated to L2 for deep inspection
        if any(token in cmd for token in ["|", ";", "&&", "||", "`", "$(", "curl", "wget", "nc", "bash -c", "eval"]):
            return None

        # 4. Check Safe Whitelist (Instant ALLOW)
        normalized_cmd = cmd.lower()
        if normalized_cmd == "ls" or any(normalized_cmd.startswith(prefix) for prefix in SAFE_COMMAND_PREFIXES):
            return EvaluationResult(
                action=ActionEnum.ALLOW,
                risk_level=RiskLevel.LOW,
                verdict=SecurityVerdict(
                    p_allow=0.99,
                    p_block=0.0,
                    p_confirm=0.01,
                    is_destructive=False,
                    is_exfiltration=False,
                ),
                reasons=["L1 Whitelist: Deterministic safe read-only operation"],
                evaluator_tier="L1_FAST_RULE",
                context=ctx,
            )

        # Non-deterministic: Escalate to L2
        return None
