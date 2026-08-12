from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path

from .integrations import state_dir
from .models import Assessment, CommandContext, Decision


SECRET_PATTERNS = (
    re.compile(r"(?i)(--?(?:password|passwd|token|secret|api[-_]?key|authorization)\s*[= ]\s*)(\S+)"),
    re.compile(r"(?i)(https?://[^\s:/]+:)([^@\s]+)(@)"),
    re.compile(r"(?i)(bearer\s+)([a-z0-9._~+/-]+=*)"),
    re.compile(r"(?i)((?:aws_secret_access_key|client_secret|private_key)\s*[=:]\s*)(\S+)"),
)


def reports_dir() -> Path:
    return state_dir() / "manager-reports"


def redact_command(command: str) -> str:
    redacted = command
    for pattern in SECRET_PATTERNS:
        if pattern.groups == 3:
            redacted = pattern.sub(r"\1[REDACTED]\3", redacted)
        else:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted[:2000]


def should_escalate(ctx: CommandContext, result: Assessment) -> bool:
    threshold = max(1, min(100, int(os.environ.get("UIG_MANAGER_REPORT_THRESHOLD", "70"))))
    privileged_anomaly = (ctx.is_root or ctx.is_admin) and ctx.anomaly_score >= 20 and result.risk_score >= 40
    unusual = ctx.anomaly_score >= 25
    return result.risk_score >= threshold or result.decision is Decision.BLOCK or privileged_anomaly or unusual


def queue_manager_report(ctx: CommandContext, result: Assessment, executed: bool, exit_code: int | None) -> Path | None:
    if not should_escalate(ctx, result):
        return None
    directory = reports_dir()
    directory.mkdir(parents=True, exist_ok=True)
    report_id = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:10]}"
    command = redact_command(ctx.command)
    report = {
        "schema_version": 1,
        "report_id": report_id,
        "created_at": time.time(),
        "manager": os.environ.get("UIG_MANAGER_ID", "unconfigured"),
        "subject": {
            "user": ctx.user_name,
            "privilege_level": ctx.privilege_level,
            "is_root": ctx.is_root,
            "is_admin": ctx.is_admin,
            "cwd": ctx.cwd,
        },
        "command": command,
        "command_hash": hashlib.sha256(ctx.command.encode("utf-8")).hexdigest(),
        "purpose": ctx.purpose,
        "decision": result.decision.value,
        "risk_score": result.risk_score,
        "anomaly_score": ctx.anomaly_score,
        "signals": [
            {"name": signal.name, "score": signal.score, "detail": signal.detail}
            for signal in result.signals if signal.score > 0
        ],
        "external_sources": list(ctx.external_sources),
        "executed": executed,
        "exit_code": exit_code,
    }
    target = directory / f"{report_id}.json"
    temporary = directory / f".{report_id}.tmp"
    temporary.write_text(json.dumps(report, indent=2), encoding="utf-8")
    os.replace(temporary, target)
    return target


def pending_report_count() -> int:
    try:
        return sum(1 for _ in reports_dir().glob("*.json"))
    except OSError:
        return 0
