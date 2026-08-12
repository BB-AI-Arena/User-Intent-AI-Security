from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any


def _history_file() -> Path:
    return Path(os.environ.get("UIG_STATE_DIR", Path.home() / ".intentgate")) / "history.jsonl"


def command_family(command: str) -> str:
    tokens = re.findall(r"[a-z0-9_.-]+", command.lower())
    return " ".join(tokens[:2]) if tokens else "unknown"


def assess_anomaly(command: str, *, user_name: str | None = None, limit: int = 500) -> dict[str, Any]:
    try:
        lines = _history_file().read_text(encoding="utf-8").splitlines()[-limit:]
    except OSError:
        return {"score": 0, "details": [], "sample_size": 0}
    families: Counter[str] = Counter()
    for line in lines:
        try:
            item = json.loads(line)
            if user_name and item.get("user_name") not in {None, user_name}:
                continue
            families[command_family(str(item.get("command", "")))] += 1
        except (json.JSONDecodeError, TypeError):
            continue
    sample_size = sum(families.values())
    if sample_size < 20:
        return {"score": 0, "details": ["Behavioral baseline is still learning."], "sample_size": sample_size}
    family = command_family(command)
    frequency = families[family]
    rarity = -math.log2((frequency + 1) / (sample_size + len(families) + 1))
    score = min(40, max(0, round((rarity - 2) * 10)))
    details = [f"Command family '{family}' appeared {frequency} time(s) in {sample_size} prior gated commands."]
    return {"score": score, "details": details, "sample_size": sample_size}
