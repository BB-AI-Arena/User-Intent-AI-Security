from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(frozen=True)
class Signal:
    name: str
    score: int
    detail: str


@dataclass(frozen=True)
class CommandContext:
    cwd: str
    command: str
    argv: tuple[str, ...]
    purpose: str | None = None
    recent_commands: tuple[str, ...] = ()
    git_root: str | None = None
    git_branch: str | None = None
    git_dirty: bool = False
    project_signals: tuple[str, ...] = ()
    provenance_risk: int = 0
    provenance_details: tuple[str, ...] = ()
    external_risk: int = 0
    external_sources: tuple[str, ...] = ()
    external_details: tuple[str, ...] = ()
    user_name: str = "unknown"
    is_root: bool = False
    is_admin: bool = False
    privilege_level: str = "standard"
    anomaly_score: int = 0
    anomaly_details: tuple[str, ...] = ()


@dataclass
class Assessment:
    decision: Decision
    risk_score: int
    signals: list[Signal] = field(default_factory=list)
    latency_ms: float = 0.0
    command_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["decision"] = self.decision.value
        return result
