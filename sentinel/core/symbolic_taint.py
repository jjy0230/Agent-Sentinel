"""Symbolic Taint and Variable Propagation Analyzer for Shell Scripts.

Performs static abstract interpretation and data-flow taint tracking on shell commands
to resolve dynamic variable concatenation (e.g. A="c"; B="url"; $A$B $TARGET)
and detect data flow from sensitive sources to network or destructive sinks.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class TaintReport:
    """Findings from symbolic taint and variable propagation analysis."""
    resolved_commands: List[str]
    is_tainted_exfiltration: bool
    is_tainted_destruction: bool
    is_spliced_obfuscation: bool = False
    tainted_variables: Dict[str, str] = field(default_factory=dict)
    symbol_table: Dict[str, str] = field(default_factory=dict)
    propagated_warnings: List[str] = field(default_factory=list)


class SymbolicTaintAnalyzer:
    """Evaluates data flow between sensitive file sources and communication sinks."""

    SENSITIVE_SOURCES = {
        ".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials",
        ".env", "credentials.db", "/etc/shadow", "/etc/passwd",
        "id_rsa", "authorized_keys"
    }

    NETWORK_SINKS = {
        "curl", "wget", "nc", "ncat", "netcat", "socat",
        "ssh", "scp", "sftp", "telnet"
    }

    DESTRUCTIVE_SINKS = {
        "rm", "dd", "shred", "truncate", "mkfs", "chown", "chmod"
    }

    def __init__(self) -> None:
        # Matches: VAR="val" or VAR='val' or export VAR="val" or VAR=val
        self._re_assignment = re.compile(
            r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=[\"']?([^\"';\n]+)[\"']?\s*$",
            re.MULTILINE
        )
        # Matches inline chained assignments: A="c"; B="url"
        self._re_chained_assign = re.compile(
            r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=[\"']?([^\"';\s]+)[\"']?"
        )

    def analyze(self, raw_script: str) -> TaintReport:
        """Trace variable definitions and propagate values to resolve obfuscated invocations."""
        symbols: Dict[str, str] = {}
        tainted_vars: Dict[str, str] = {}
        warnings: List[str] = []
        resolved_cmds: List[str] = []

        is_tainted_exfiltration = False
        is_tainted_destruction = False
        is_spliced_obfuscation = False

        # Check for dynamic variable splicing in raw script
        if re.search(r"\$[A-Za-z0-9_]+\$[A-Za-z0-9_]+|\$\{[A-Za-z0-9_]+\}\$\{[A-Za-z0-9_]+\}", raw_script):
            is_spliced_obfuscation = True
            warnings.append("Detected variable splicing to construct obfuscated command")

        # Step 1: Extract all variable declarations into symbol table
        for match in self._re_chained_assign.finditer(raw_script):
            var_name, var_val = match.groups()
            symbols[var_name] = var_val

            # Check if assigned value contains a sensitive source
            if any(src in var_val.lower() for src in self.SENSITIVE_SOURCES):
                tainted_vars[var_name] = var_val
                warnings.append(f"Variable '${var_name}' assigned sensitive source: {var_val}")

        # Step 2: Split script into statements and substitute variables
        statements = re.split(r"(?:;|\n|&&|\|\|)+", raw_script)

        for stmt in statements:
            cleaned = stmt.strip()
            if not cleaned or cleaned.startswith("#") or self._re_assignment.match(cleaned):
                continue

            # Substitute ${VAR} or $VAR from symbol table
            resolved = cleaned
            for var_name, var_val in symbols.items():
                resolved = resolved.replace(f"${{{var_name}}}", var_val)
                resolved = resolved.replace(f"${var_name}", var_val)

            resolved_cmds.append(resolved)

            # Step 3: Check if tainted variable or resolved string hits a sink
            lower_res = resolved.lower()
            tokens = set(re.findall(r"\b[a-z0-9_.-]+\b", lower_res))

            hits_net = bool(tokens & self.NETWORK_SINKS)
            hits_destr = bool(tokens & self.DESTRUCTIVE_SINKS)
            has_sensitive = any(src in lower_res for src in self.SENSITIVE_SOURCES) or any(
                var in cleaned for var in tainted_vars
            )

            # Data-flow taint: Sensitive Source -> Network Sink
            if has_sensitive and (hits_net or "|" in resolved):
                is_tainted_exfiltration = True
                warnings.append(f"Taint violation: Sensitive source flowing into network sink in '{resolved}'")

            # Data-flow taint: Destructive Sink
            if hits_destr and any(arg in resolved for arg in ["-rf", "-f", "/dev/", "truncate", ">"]):
                is_tainted_destruction = True
                warnings.append(f"Taint violation: Dangerous filesystem mutation in '{resolved}'")

        return TaintReport(
            resolved_commands=resolved_cmds,
            is_tainted_exfiltration=is_tainted_exfiltration,
            is_tainted_destruction=is_tainted_destruction,
            is_spliced_obfuscation=is_spliced_obfuscation,
            tainted_variables=tainted_vars,
            symbol_table=symbols,
            propagated_warnings=warnings,
        )
