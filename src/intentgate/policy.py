from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


DEFAULT_POLICY = {
    "name": "default",
    "version": 1,
    "review_threshold": 40,
    "block_threshold": 85,
}


def _policy_path() -> Path:
    state_dir = Path(os.environ.get("UIG_STATE_DIR", Path.home() / ".intentgate"))
    return state_dir / "policy.json"


def _validated(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("policy must be a JSON object")
    review = int(value.get("review_threshold", DEFAULT_POLICY["review_threshold"]))
    block = int(value.get("block_threshold", DEFAULT_POLICY["block_threshold"]))
    if not 1 <= review < block <= 100:
        raise ValueError("thresholds must satisfy 1 <= review < block <= 100")
    name = str(value.get("name", DEFAULT_POLICY["name"])).strip()[:80] or "default"
    version = max(1, int(value.get("version", DEFAULT_POLICY["version"])))
    return {
        "name": name,
        "version": version,
        "review_threshold": review,
        "block_threshold": block,
    }


def load_policy() -> dict[str, Any]:
    try:
        return _validated(json.loads(_policy_path().read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return dict(DEFAULT_POLICY)


def save_policy(value: object) -> dict[str, Any]:
    current = load_policy()
    incoming = _validated(value)
    incoming["version"] = current["version"] + 1
    path = _policy_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(incoming, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    return incoming
