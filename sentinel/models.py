"""Data models for Agent-Sentinel."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional
import json


class ActionEnum(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_HUMAN_CONFIRM = "REQUIRE_HUMAN_CONFIRM"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class CommandContext:
    """Context of the command submitted by an AI Agent."""
    raw_command: str
    agent_intent: Optional[str] = None
    workspace_path: Optional[str] = None
    session_id: Optional[str] = None
    caller_agent: Optional[str] = None  # e.g., 'claude-code', 'cursor', 'open-interpreter'
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CommandContext":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class SecurityVerdict:
    """Probabilistic output and flags from the decision engine."""
    p_allow: float = 0.0
    p_block: float = 0.0
    p_confirm: float = 0.0
    is_destructive: bool = False
    is_exfiltration: bool = False
    is_obfuscated: bool = False
    is_privilege_escalation: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationResult:
    """Final decision output from Sentinel Gateway."""
    action: ActionEnum
    risk_level: RiskLevel
    verdict: SecurityVerdict
    reasons: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    evaluator_tier: str = "L1_FAST_RULE"  # 'L1_FAST_RULE' or 'L2_ANYJEV' or 'L2_MOCK'
    context: Optional[CommandContext] = None

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["action"] = self.action.value
        res["risk_level"] = self.risk_level.value
        return res

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvaluationResult":
        action = ActionEnum(data["action"])
        risk_level = RiskLevel(data.get("risk_level", "LOW"))
        verdict = SecurityVerdict(**data.get("verdict", {}))
        ctx_data = data.get("context")
        ctx = CommandContext.from_dict(ctx_data) if ctx_data else None
        return cls(
            action=action,
            risk_level=risk_level,
            verdict=verdict,
            reasons=data.get("reasons", []),
            latency_ms=data.get("latency_ms", 0.0),
            evaluator_tier=data.get("evaluator_tier", "L1_FAST_RULE"),
            context=ctx,
        )
