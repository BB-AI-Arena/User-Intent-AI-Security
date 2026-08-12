from __future__ import annotations

import json
import time
from pathlib import Path

from .context import HISTORY_FILE
from .models import Assessment, CommandContext
from .reporting import queue_manager_report


def record(ctx: CommandContext, result: Assessment, executed: bool, exit_code: int | None = None) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "timestamp": time.time(),
        "command": ctx.command,
        "cwd": ctx.cwd,
        "user_name": ctx.user_name,
        "privilege_level": ctx.privilege_level,
        "is_root": ctx.is_root,
        "is_admin": ctx.is_admin,
        "anomaly_score": ctx.anomaly_score,
        "purpose": ctx.purpose,
        "decision": result.decision.value,
        "risk_score": result.risk_score,
        "latency_ms": result.latency_ms,
        "signals": [signal.name for signal in result.signals],
        "fingerprint": result.command_fingerprint,
        "executed": executed,
        "exit_code": exit_code,
    }
    with HISTORY_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    try:
        queue_manager_report(ctx, result, executed, exit_code)
    except OSError:
        # Reporting is asynchronous and must not change the command's exit behavior.
        pass
