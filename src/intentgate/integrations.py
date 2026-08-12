from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any


MAX_SIGNALS = 512


def state_dir() -> Path:
    return Path(os.environ.get("UIG_STATE_DIR", Path.home() / ".intentgate"))


def signal_store_path() -> Path:
    return state_dir() / "external-signals.json"


def _load() -> dict[str, Any]:
    try:
        data = json.loads(signal_store_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"signals": []}
    except (OSError, json.JSONDecodeError, TypeError):
        return {"schema_version": 1, "updated_at": 0, "signals": []}


def _write(data: dict[str, Any]) -> None:
    path = signal_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, path)


def normalize_signal(payload: dict[str, Any]) -> dict[str, Any]:
    now = time.time()
    source = str(payload.get("source", "unknown"))[:80]
    event_id = str(payload.get("event_id") or payload.get("id") or "")[:160]
    if not event_id:
        digest = hashlib.blake2s(json.dumps(payload, sort_keys=True).encode("utf-8"), digest_size=10).hexdigest()
        event_id = digest
    score = max(0, min(100, int(float(payload.get("score", 0)))))
    confidence = max(0.0, min(1.0, float(payload.get("confidence", 1.0))))
    ttl = max(1, min(604_800, int(payload.get("ttl_seconds", 300))))
    scope = payload.get("scope") if isinstance(payload.get("scope"), dict) else {}
    return {
        "source": source,
        "event_id": event_id,
        "score": score,
        "confidence": confidence,
        "detail": str(payload.get("detail", ""))[:500],
        "observed_at": float(payload.get("observed_at", now)),
        "expires_at": now + ttl,
        "scope": {str(k): str(v) for k, v in scope.items() if k in {"device", "user", "project"}},
    }


def ingest(payloads: list[dict[str, Any]]) -> int:
    now = time.time()
    data = _load()
    current = {
        (str(item.get("source")), str(item.get("event_id"))): item
        for item in data.get("signals", [])
        if float(item.get("expires_at", 0)) > now
    }
    for payload in payloads:
        item = normalize_signal(payload)
        current[(item["source"], item["event_id"])] = item
    signals = sorted(current.values(), key=lambda item: float(item["observed_at"]), reverse=True)[:MAX_SIGNALS]
    _write({"schema_version": 1, "updated_at": now, "signals": signals})
    return len(payloads)


def _matches_scope(item_scope: dict[str, Any], requested: dict[str, str | None]) -> bool:
    for key, expected in item_scope.items():
        actual = requested.get(key)
        if expected and actual and str(expected).lower() != str(actual).lower():
            return False
    return True


def read_posture(*, device: str | None = None, user: str | None = None, project: str | None = None) -> dict[str, Any]:
    now = time.time()
    requested = {"device": device, "user": user, "project": project}
    active = [
        item for item in _load().get("signals", [])
        if float(item.get("expires_at", 0)) > now and _matches_scope(item.get("scope", {}), requested)
    ]
    weighted = sorted(
        [(float(item.get("score", 0)) * float(item.get("confidence", 1)), item) for item in active],
        reverse=True,
        key=lambda pair: pair[0],
    )
    if not weighted:
        return {"risk_score": 0, "sources": [], "details": [], "active_signals": 0}
    highest = weighted[0][0]
    corroboration = min(20.0, sum(value * 0.15 for value, _ in weighted[1:]))
    risk = min(100, round(highest + corroboration))
    sources = sorted({str(item.get("source", "unknown")) for _, item in weighted})
    details = [str(item.get("detail", "")) for _, item in weighted[:5] if item.get("detail")]
    return {"risk_score": risk, "sources": sources, "details": details, "active_signals": len(weighted)}


def source_postures() -> dict[str, int]:
    now = time.time()
    result: dict[str, int] = {}
    for item in _load().get("signals", []):
        if float(item.get("expires_at", 0)) <= now:
            continue
        source = str(item.get("source", "unknown"))
        effective = round(float(item.get("score", 0)) * float(item.get("confidence", 1)))
        result[source] = max(result.get(source, 0), effective)
    return result
