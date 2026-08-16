from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import Assessment, CommandContext, Decision, Signal


ZONE_NAMES = ("edge", "application", "observability", "management", "outbound")
FLOW_IDS = (
    "edge>application",
    "observability>application",
    "management>observability",
    "application>outbound",
    "outbound>external",
)

DEFAULT_CONTROLS: dict[str, Any] = {
    "version": 1,
    "zero_trust": {
        "enforcement_mode": "review",
        "identity_required": True,
        "purpose_required": True,
        "device_posture_required": True,
        "behavior_monitoring": True,
        "step_up_threshold": 60,
        "session_ttl_minutes": 30,
    },
    "microsegmentation": {
        "default_action": "deny",
        "service_identity": True,
        "log_denied": True,
        "enabled_zones": list(ZONE_NAMES),
        "allowed_flows": list(FLOW_IDS),
        "deployment_status": "compose-enforced",
    },
}


def _path() -> Path:
    return Path(os.environ.get("UIG_STATE_DIR", Path.home() / ".intentgate")) / "trust-controls.json"


def _bool(value: object, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _validated(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("trust controls must be a JSON object")
    zero = value.get("zero_trust", {})
    micro = value.get("microsegmentation", {})
    if not isinstance(zero, dict) or not isinstance(micro, dict):
        raise ValueError("zero_trust and microsegmentation must be objects")
    mode = str(zero.get("enforcement_mode", "review"))
    if mode not in {"monitor", "review", "enforce"}:
        raise ValueError("enforcement_mode must be monitor, review, or enforce")
    threshold = int(zero.get("step_up_threshold", 60))
    ttl = int(zero.get("session_ttl_minutes", 30))
    if not 1 <= threshold <= 100:
        raise ValueError("step_up_threshold must be between 1 and 100")
    if not 5 <= ttl <= 1440:
        raise ValueError("session_ttl_minutes must be between 5 and 1440")
    default_action = str(micro.get("default_action", "deny"))
    if default_action not in {"deny", "review"}:
        raise ValueError("default_action must be deny or review")
    enabled = micro.get("enabled_zones", list(ZONE_NAMES))
    flows = micro.get("allowed_flows", list(FLOW_IDS))
    if not isinstance(enabled, list) or not isinstance(flows, list):
        raise ValueError("enabled_zones and allowed_flows must be arrays")
    unknown_zones = set(map(str, enabled)) - set(ZONE_NAMES)
    unknown_flows = set(map(str, flows)) - set(FLOW_IDS)
    if unknown_zones or unknown_flows:
        raise ValueError("configuration contains an unknown zone or flow")
    deployment_status = str(micro.get("deployment_status", "compose-enforced"))
    if deployment_status not in {"compose-enforced", "redeploy-required"}:
        deployment_status = "redeploy-required"
    return {
        "version": max(1, int(value.get("version", 1))),
        "zero_trust": {
            "enforcement_mode": mode,
            "identity_required": _bool(zero.get("identity_required"), True),
            "purpose_required": _bool(zero.get("purpose_required"), True),
            "device_posture_required": _bool(zero.get("device_posture_required"), True),
            "behavior_monitoring": _bool(zero.get("behavior_monitoring"), True),
            "step_up_threshold": threshold,
            "session_ttl_minutes": ttl,
        },
        "microsegmentation": {
            "default_action": default_action,
            "service_identity": _bool(micro.get("service_identity"), True),
            "log_denied": _bool(micro.get("log_denied"), True),
            "enabled_zones": [name for name in ZONE_NAMES if name in enabled],
            "allowed_flows": [flow for flow in FLOW_IDS if flow in flows],
            "deployment_status": deployment_status,
        },
    }


def load_trust_controls() -> dict[str, Any]:
    try:
        return _validated(json.loads(_path().read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return json.loads(json.dumps(DEFAULT_CONTROLS))


def save_trust_controls(value: object) -> dict[str, Any]:
    current = load_trust_controls()
    incoming = _validated(value)
    incoming["version"] = current["version"] + 1
    current_micro = {key: val for key, val in current["microsegmentation"].items() if key != "deployment_status"}
    incoming_micro = {key: val for key, val in incoming["microsegmentation"].items() if key != "deployment_status"}
    incoming["microsegmentation"]["deployment_status"] = (
        "redeploy-required" if incoming_micro != current_micro else current["microsegmentation"]["deployment_status"]
    )
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(incoming, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    return incoming


def apply_zero_trust(ctx: CommandContext, result: Assessment) -> Assessment:
    """Apply the saved step-up profile without weakening an existing decision."""
    controls = load_trust_controls()["zero_trust"]
    mode = controls["enforcement_mode"]
    if mode == "monitor":
        return result
    added: list[Signal] = []
    if controls["purpose_required"] and not ctx.purpose:
        added.append(Signal("zero-trust-intent-required", 15, "Zero-trust policy requires declared intent for this action."))
    if controls["device_posture_required"] and not ctx.external_sources:
        added.append(Signal("zero-trust-posture-unavailable", 5, "No current device or identity posture feed is available."))
    score = min(100, result.risk_score + sum(item.score for item in added))
    decision = result.decision
    step_up = score >= int(controls["step_up_threshold"])
    if decision is Decision.ALLOW and (step_up or (mode == "enforce" and bool(added))):
        decision = Decision.REVIEW
        added.append(Signal("zero-trust-step-up", 0, "Zero-trust policy requires an additional human decision."))
    return Assessment(
        decision=decision,
        risk_score=score,
        signals=[*result.signals, *added],
        latency_ms=result.latency_ms,
        command_fingerprint=result.command_fingerprint,
        policy_name=result.policy_name,
        policy_version=result.policy_version,
    )
