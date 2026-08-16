from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from threading import Lock
from typing import Any

from .models import Assessment, CommandContext


_LOCK = Lock()


def _reviews_path() -> Path:
    state_dir = Path(os.environ.get("UIG_STATE_DIR", Path.home() / ".intentgate"))
    return state_dir / "reviews.json"


def _read() -> list[dict[str, Any]]:
    try:
        value = json.loads(_reviews_path().read_text(encoding="utf-8"))
        return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _write(items: list[dict[str, Any]]) -> None:
    path = _reviews_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(items, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def create_review(ctx: CommandContext, result: Assessment) -> dict[str, Any]:
    item = {
        "id": uuid.uuid4().hex[:12],
        "created_at": time.time(),
        "updated_at": time.time(),
        "status": "pending",
        "command": ctx.command,
        "purpose": ctx.purpose,
        "cwd": ctx.cwd,
        "risk_score": result.risk_score,
        "signals": [signal.name for signal in result.signals if signal.score > 0],
        "decision_note": None,
    }
    with _LOCK:
        items = _read()
        items.append(item)
        _write(items[-500:])
    return item


def list_reviews(limit: int = 100) -> list[dict[str, Any]]:
    return list(reversed(_read()[-max(1, min(limit, 500)):]))


def decide_review(review_id: str, status: str, note: str | None = None) -> dict[str, Any] | None:
    if status not in {"approved", "denied"}:
        raise ValueError("status must be approved or denied")
    with _LOCK:
        items = _read()
        selected = None
        for item in items:
            if item.get("id") == review_id:
                item["status"] = status
                item["updated_at"] = time.time()
                item["decision_note"] = (note or "").strip()[:500] or None
                selected = item
                break
        if selected is not None:
            _write(items)
        return selected
