"""AST Pruner and Shell Obfuscation Detector.

Performs static analysis and token budget pruning on multi-line shell scripts
to prevent Prefill latency blowup (>200ms) on long commands while detecting
obfuscation (Base64 pipes, eval, dynamic string expansions).
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple


@dataclass
class PrunedAnalysis:
    """Result of AST and lexical pruning."""
    pruned_content: str
    is_obfuscated: bool
    is_truncated: bool
    extracted_network_calls: List[str]
    extracted_fs_mutations: List[str]
    warnings: List[str]


class ASTPruner:
    """Extracts security-critical lines and detects dynamic execution patterns."""

    NETWORK_KEYWORDS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "rsync", "ftp", "telnet"}
    MUTATION_KEYWORDS = {"rm", "mv", "cp", "dd", "chmod", "chown", "truncate", "mkfs", "fdisk", "shred"}
    DANGEROUS_INTERPRETERS = {"bash", "sh", "zsh", "python", "perl", "ruby", "node"}

    def __init__(self, token_budget_chars: int = 1200) -> None:
        self.token_budget_chars = token_budget_chars

        # Obfuscation regex detectors
        self._re_base64_decode = re.compile(r"(?:base64\s+-(?:d|D|--decode)|openssl\s+enc\s+-d|xxd\s+-r)", re.IGNORECASE)
        self._re_eval_pipeline = re.compile(r"\|\s*(?:sh|bash|zsh|eval|exec)\b", re.IGNORECASE)
        self._re_dynamic_eval = re.compile(r"\b(?:eval|exec)\s+(?:\"|\'|\$)", re.IGNORECASE)
        self._re_env_splicing = re.compile(r"\$\{[A-Za-z0-9_]+:[0-9:]+\}|\$[A-Za-z0-9_]+\$[A-Za-z0-9_]+")
        self._re_tcp_redirect = re.compile(r"/dev/(?:tcp|udp)/[a-zA-Z0-9_.-]+/\d+", re.IGNORECASE)
        self._re_remote_subshell = re.compile(r"(?:\$\(|`)\s*(?:curl|wget|nc)\b|\b(?:ba)?sh\s+-c\s+[\"'].*?\$\(", re.IGNORECASE)

    def analyze(self, raw_script: str) -> PrunedAnalysis:
        """Analyze and prune raw shell script to fit AnyJev prefill budget.

        Security Principle:
        - NEVER drop obfuscated lines (Fail-closed).
        - Strip low-entropy boilerplate (comments, repetitive echoes, blank lines).
        - Retain high-risk nodes (network, filesystem writes, dynamic evals).
        """
        lines = [line.strip() for line in raw_script.splitlines() if line.strip()]
        if not lines:
            return PrunedAnalysis(
                pruned_content="",
                is_obfuscated=False,
                is_truncated=False,
                extracted_network_calls=[],
                extracted_fs_mutations=[],
                warnings=[],
            )

        warnings: List[str] = []
        is_obfuscated = False

        # 1. Obfuscation detection across entire script
        full_text = " ".join(lines)
        if self._re_base64_decode.search(full_text):
            is_obfuscated = True
            warnings.append("Detected Base64/Hex decoding pipeline")

        if self._re_eval_pipeline.search(full_text):
            is_obfuscated = True
            warnings.append("Detected piped execution into shell interpreter")

        if self._re_dynamic_eval.search(full_text):
            is_obfuscated = True
            warnings.append("Detected dynamic eval/exec invocation")

        if self._re_env_splicing.search(full_text):
            is_obfuscated = True
            warnings.append("Detected variable slicing/splicing (potential obfuscation)")

        if self._re_tcp_redirect.search(full_text):
            is_obfuscated = True
            warnings.append("Detected direct /dev/tcp socket redirection")

        if self._re_remote_subshell.search(full_text):
            is_obfuscated = True
            warnings.append("Detected remote payload execution in subshell $(curl/wget)")

        # 2. Extract critical command lines
        network_calls: List[str] = []
        fs_mutations: List[str] = []
        critical_lines: List[str] = []
        benign_lines: List[str] = []

        for line in lines:
            # Skip pure comments
            if line.startswith("#"):
                continue

            lower_line = line.lower()
            tokens = set(re.findall(r"\b[a-z0-9_-]+\b", lower_line))

            has_net = bool(tokens & self.NETWORK_KEYWORDS)
            has_mutation = bool(tokens & self.MUTATION_KEYWORDS) or ">" in line or ">>" in line
            has_obfuscation = is_obfuscated and any(
                k in lower_line for k in ["base64", "eval", "sh", "bash", "curl", "dev/tcp"]
            )

            if has_net:
                network_calls.append(line)
            if has_mutation:
                fs_mutations.append(line)

            if has_net or has_mutation or has_obfuscation or "sudo " in lower_line:
                critical_lines.append(line)
            else:
                benign_lines.append(line)

        # 3. Assemble pruned representation within token budget
        # Always prioritize critical lines first
        selected_lines = list(critical_lines)
        is_truncated = False

        # If room remains, add surrounding context lines up to budget
        budget_remaining = self.token_budget_chars - sum(len(l) for l in selected_lines)
        for line in benign_lines:
            if budget_remaining - len(line) - 1 >= 0:
                selected_lines.append(line)
                budget_remaining -= (len(line) + 1)
            else:
                is_truncated = True
                break

        pruned_text = "\n".join(selected_lines)
        if len(pruned_text) > self.token_budget_chars:
            pruned_text = pruned_text[: self.token_budget_chars]
            is_truncated = True

        return PrunedAnalysis(
            pruned_content=pruned_text,
            is_obfuscated=is_obfuscated,
            is_truncated=is_truncated,
            extracted_network_calls=network_calls,
            extracted_fs_mutations=fs_mutations,
            warnings=warnings,
        )
