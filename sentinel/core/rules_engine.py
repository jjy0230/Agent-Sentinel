"""L1 Deterministic Fast-Path Filter.

Evaluates terminal commands in microseconds (< 0.05ms) using pre-compiled regex
and pattern matching to handle ~80-90% of deterministic commands (safe queries or obvious attacks)
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
    "git remote",
    "git rev-parse",
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
    "pnpm -v",
    "pnpm --version",
    "yarn -v",
    "yarn --version",
    "python --version",
    "python -V",
    "python3 --version",
    "python3 -V",
    "cargo --version",
    "cargo check",
    "cargo build",
    "go version",
    "rustc --version",
    "docker ps",
    "docker images",
    "docker version",
    "kubectl get ",
    "kubectl describe ",
    "pytest ",
    "date",
    "uptime",
    "ps aux",
    "ps -ef",
)

# Safe pipe filter utilities (when chained with safe read commands)
SAFE_PIPE_FILTERS = {"grep", "head", "tail", "wc", "sort", "uniq", "awk", "cut", "jq", "less", "more"}

# Hard Blacklist - Unrecoverable destructive attacks & immediate compromises
HARD_BLACKLIST_PATTERNS = [
    (r"rm\s+-(?:r[fF]|f[rR]|rf)\s+(?:/|/\*|~|~/\*|\$HOME|\$HOME/\*)", "Catastrophic filesystem purge"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Fork bomb denial of service"),
    (r"mkfs(?:\.[a-z0-9]+)?\s+/dev/[a-z0-9]+", "Raw filesystem format destruction"),
    (r"dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/[a-z0-9]+", "Raw block device wipe"),
    (r">/dev/sd[a-z0-9]+", "Raw disk redirection destruction"),
    (r"chmod\s+-(?:R|r)\s+777\s+/", "Root privilege degradation"),
    (r"chown\s+-(?:R|r)\s+[a-z0-9_:]+\s+/", "Root ownership degradation"),
    (r"sudo\s+rm\s+-(?:r[fF]|f[rR]|rf)\s+/", "Privileged filesystem deletion"),
    (r"crontab\s+-r", "Unauthorized cron table deletion"),
    (r">>\s*~?/\.ssh/authorized_keys", "Unauthorized SSH backdoor injection"),
    (r"(?:nc|ncat|netcat)\s+(?:-e|-c)\s+/bin/(?:ba)?sh", "Netcat reverse shell backdoor"),
    (r"bash\s+-i\s+>&?\s*/dev/tcp/", "Direct interactive Bash TCP reverse shell"),
    (r"iptables\s+-F|ufw\s+disable", "Local firewall flush / disable"),
    (r"shred\s+.*(?:/etc/|/var/log/)", "Sensitive system log or configuration shredding"),
]

# Sensitive patterns that MUST trigger L2 deep evaluation or immediate flag
SENSITIVE_TARGETS = [
    r"~?/\.ssh/id_[a-z0-9_]+",
    r"~?/\.aws/credentials",
    r"~?/\.config/gcloud/",
    r"credentials(?:\.db)?",
    r"\.env(?:\.[a-zA-Z0-9]+)?$",
    r"id_rsa",
    r"/etc/shadow",
    r"/etc/passwd",
    r"authorized_keys",
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

    def _is_safe_read_pipe(self, cmd: str) -> bool:
        """Check if a pipeline command consists purely of safe read prefixes and safe filters."""
        segments = [s.strip() for s in cmd.split("|")]
        if len(segments) <= 1:
            return False

        first = segments[0].lower()
        if not any(first == prefix or first.startswith(prefix) for prefix in SAFE_COMMAND_PREFIXES):
            return False

        # All subsequent pipeline steps must be pure reading/filtering tools
        for seg in segments[1:]:
            parts = seg.split()
            if not parts:
                return False
            tool = parts[0].lower()
            if tool not in SAFE_PIPE_FILTERS:
                return False
            # Check for suspicious redirection or shell inside filter
            if any(c in seg for c in [">", ";", "`", "$("]):
                return False

        return True

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

        # 3. Check for Safe Pipeline (e.g. ps aux | grep node, git log | head -n 5)
        if "|" in cmd and self._is_safe_read_pipe(cmd):
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
                reasons=["L1 Whitelist: Safe read pipeline with benign filter"],
                evaluator_tier="L1_FAST_RULE",
                context=ctx,
            )

        # 4. Check for dynamic execution, network calls or dangerous tokens
        if any(token in cmd for token in ["|", ";", "&&", "||", "`", "$(", "curl", "wget", "nc", "bash -c", "eval"]):
            return None

        # 5. Check Safe Whitelist (Instant ALLOW)
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
