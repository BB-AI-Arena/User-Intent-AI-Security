from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .deployments import list_endpoints


DEFAULT_SECURITY_POLICIES: tuple[dict[str, Any], ...] = (
    {
        "id": "endpoint-av",
        "name": "Endpoint antivirus",
        "domain": "AV",
        "description": "Real-time file, process, memory, and removable-media protection.",
        "enabled": True,
        "enforcement_mode": "enforce",
        "assigned_groups": ["windows", "linux", "macos"],
        "rules": ["Real-time protection", "Cloud-delivered detection", "Tamper protection", "Scheduled full scan"],
        "source": "endpoint-protection-baseline",
    },
    {
        "id": "malware-prevention",
        "name": "Malware prevention",
        "domain": "MALWARE",
        "description": "Blocks known malware, suspicious scripts, ransomware behavior, and persistence techniques.",
        "enabled": True,
        "enforcement_mode": "enforce",
        "assigned_groups": ["high-value", "privileged-access", "privileged-dev", "engineering"],
        "rules": ["Known-malware deny", "Ransomware behavior block", "Script reputation", "Persistence prevention"],
        "source": "malware-prevention-baseline",
    },
    {
        "id": "data-loss-prevention",
        "name": "Data loss prevention",
        "domain": "DLP",
        "description": "Detects sensitive-data movement to unapproved destinations and removable media.",
        "enabled": True,
        "enforcement_mode": "review",
        "assigned_groups": ["finance", "high-value", "sales"],
        "rules": ["Financial data classification", "Secrets and credentials", "External upload review", "Removable-media control"],
        "source": "dlp-baseline",
    },
    {
        "id": "behavior-monitoring",
        "name": "Behavior monitoring",
        "domain": "UEBA",
        "description": "Correlates command rarity, velocity, privilege, sequence, and identity baselines.",
        "enabled": True,
        "enforcement_mode": "review",
        "assigned_groups": ["operations", "privileged-access", "privileged-dev", "cluster-admins"],
        "rules": ["Rare command family", "Rapid file mutation", "Privilege anomaly", "Secret-to-egress sequence"],
        "source": "intentgate-local-baseline",
    },
    {
        "id": "vulnerability-cve",
        "name": "Vulnerability & CVE scanning",
        "domain": "CVE",
        "description": "Prioritizes vulnerable software using severity, asset exposure, and known exploitation.",
        "enabled": True,
        "enforcement_mode": "enforce",
        "assigned_groups": ["windows", "linux", "macos", "high-value", "ci-runners"],
        "rules": ["Daily software inventory", "Known-exploited escalation", "Critical CVE deployment gate", "Remediation SLA tracking"],
        "source": "demo-kev-feed",
        "cve_alerts": [
            {"id": "CVE-2021-44228", "severity": "critical", "known_exploited": True, "affected_endpoints": 1, "status": "patch-required", "summary": "Log4j remote code execution exposure detected in a demo build dependency."},
            {"id": "CVE-2023-34362", "severity": "critical", "known_exploited": True, "affected_endpoints": 1, "status": "isolated", "summary": "MOVEit transfer service signature observed on a demo high-value endpoint."},
            {"id": "CVE-2024-3094", "severity": "high", "known_exploited": False, "affected_endpoints": 1, "status": "investigate", "summary": "XZ package provenance requires validation on a demo Linux runner."},
        ],
    },
)


def _path() -> Path:
    return Path(os.environ.get("UIG_STATE_DIR", Path.home() / ".intentgate")) / "security-policies.json"


def _stored() -> list[dict[str, Any]]:
    try:
        value = json.loads(_path().read_text(encoding="utf-8"))
        return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _write(value: list[dict[str, Any]]) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _coverage(policy: dict[str, Any], endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    groups = set(map(str, policy.get("assigned_groups", [])))
    matched = [item for item in endpoints if groups.intersection(map(str, item.get("security_groups", [])))]
    return {
        **policy,
        "covered_endpoint_count": len(matched),
        "total_endpoint_count": len(endpoints),
        "online_endpoint_count": sum(item.get("status") == "online" for item in matched),
        "covered_endpoints": [
            {"id": item.get("id"), "hostname": item.get("hostname"), "status": item.get("status"), "agent_version": item.get("agent_version")}
            for item in matched
        ],
    }


def list_security_policies() -> dict[str, Any]:
    defaults = {item["id"]: json.loads(json.dumps(item)) for item in DEFAULT_SECURITY_POLICIES}
    for item in _stored():
        if isinstance(item, dict) and item.get("id") in defaults:
            defaults[item["id"]].update({
                "enabled": bool(item.get("enabled", defaults[item["id"]]["enabled"])),
                "enforcement_mode": str(item.get("enforcement_mode", defaults[item["id"]]["enforcement_mode"])),
                "assigned_groups": list(item.get("assigned_groups", defaults[item["id"]]["assigned_groups"])),
            })
    endpoints = list_endpoints()
    policies = [_coverage(defaults[item["id"]], endpoints) for item in DEFAULT_SECURITY_POLICIES]
    groups = sorted({str(group) for endpoint in endpoints for group in endpoint.get("security_groups", [])})
    return {
        "policies": policies,
        "available_groups": groups,
        "summary": {
            "active": sum(item["enabled"] for item in policies),
            "domains": len(policies),
            "endpoint_count": len(endpoints),
            "known_exploited_cves": sum(alert.get("known_exploited") is True for item in policies for alert in item.get("cve_alerts", [])),
        },
        "intelligence_notice": "CVE findings use a labeled demo intelligence feed for this POC; connect an authenticated scanner and current KEV source for production.",
    }


def save_security_policy(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("security policy update must be an object")
    policy_id = str(value.get("id", ""))
    defaults = {item["id"]: item for item in DEFAULT_SECURITY_POLICIES}
    if policy_id not in defaults:
        raise ValueError("unknown security policy id")
    mode = str(value.get("enforcement_mode", defaults[policy_id]["enforcement_mode"]))
    if mode not in {"monitor", "review", "enforce"}:
        raise ValueError("enforcement_mode must be monitor, review, or enforce")
    groups = value.get("assigned_groups", defaults[policy_id]["assigned_groups"])
    if not isinstance(groups, list):
        raise ValueError("assigned_groups must be an array")
    available = set(list_security_policies()["available_groups"])
    selected_groups = sorted({str(item) for item in groups if str(item) in available})
    if not selected_groups:
        raise ValueError("at least one discovered security group is required")
    saved = {
        "id": policy_id,
        "enabled": bool(value.get("enabled", True)),
        "enforcement_mode": mode,
        "assigned_groups": selected_groups,
    }
    items = [item for item in _stored() if isinstance(item, dict) and item.get("id") != policy_id]
    items.append(saved)
    _write(items)
    return next(item for item in list_security_policies()["policies"] if item["id"] == policy_id)
