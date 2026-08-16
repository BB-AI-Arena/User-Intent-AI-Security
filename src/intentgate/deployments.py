from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from threading import Lock
from typing import Any


_LOCK = Lock()
_ENDPOINT_ID = re.compile(r"^[a-zA-Z0-9._-]{1,80}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,39}$")

_DEMO_ENDPOINTS = (
    ("dev-ws-042", "DEV-WS-042", "10.24.10.42", "Windows 11", ("engineering", "windows", "standard-trust"), "0.4.0", "online"),
    ("dev-ws-117", "DEV-WS-117", "10.24.10.117", "Windows 11", ("engineering", "windows", "privileged-dev"), "0.4.0", "online"),
    ("fin-lt-019", "FIN-LT-019", "10.24.20.19", "Windows 11", ("finance", "windows", "high-value"), None, "online"),
    ("ops-pa-003", "OPS-PA-003", "10.24.30.3", "Windows Server 2025", ("operations", "windows", "privileged-access"), "0.3.2", "online"),
    ("build-lnx-02", "BUILD-LNX-02", "10.24.40.22", "Ubuntu 24.04", ("engineering", "linux", "ci-runners"), "0.4.0", "online"),
    ("kube-admin-01", "KUBE-ADMIN-01", "10.24.30.11", "Ubuntu 24.04", ("operations", "linux", "cluster-admins"), "0.4.0", "online"),
    ("sales-lt-088", "SALES-LT-088", "10.24.50.88", "Windows 11", ("sales", "windows", "standard-trust"), None, "offline"),
    ("sec-lab-07", "SEC-LAB-07", "10.24.60.7", "macOS 15", ("security", "macos", "purple-team"), "0.4.0", "online"),
)


def _state_dir() -> Path:
    return Path(os.environ.get("UIG_STATE_DIR", Path.home() / ".intentgate"))


def _path(name: str) -> Path:
    return _state_dir() / name


def _read(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _demo_endpoints() -> list[dict[str, Any]]:
    now = time.time()
    return [
        {
            "id": endpoint_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "operating_system": operating_system,
            "security_groups": list(groups),
            "agent_version": agent_version,
            "install_state": "managed" if agent_version else "not-installed",
            "status": status,
            "last_seen": now - (22 if status == "online" else 7_440),
            "source": "demo-inventory",
        }
        for endpoint_id, hostname, ip_address, operating_system, groups, agent_version, status in _DEMO_ENDPOINTS
    ]


def list_endpoints() -> list[dict[str, Any]]:
    endpoints = _read(_path("endpoints.json"), None)
    if not isinstance(endpoints, list) or not endpoints:
        endpoints = _demo_endpoints()
        _write(_path("endpoints.json"), endpoints)
    return sorted((item for item in endpoints if isinstance(item, dict)), key=lambda item: str(item.get("hostname", "")))


def register_endpoint(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("endpoint registration must be an object")
    hostname = str(value.get("hostname", "")).strip()[:120]
    endpoint_id = str(value.get("id") or hostname.lower()).strip()
    if not hostname or not _ENDPOINT_ID.fullmatch(endpoint_id):
        raise ValueError("hostname and a valid endpoint id are required")
    groups = value.get("security_groups", [])
    if not isinstance(groups, list) or len(groups) > 20:
        raise ValueError("security_groups must be an array with at most 20 entries")
    groups = sorted({str(item).strip()[:80] for item in groups if str(item).strip()})
    endpoint = {
        "id": endpoint_id,
        "hostname": hostname,
        "ip_address": str(value.get("ip_address", "unknown"))[:80],
        "operating_system": str(value.get("operating_system", "unknown"))[:120],
        "security_groups": groups,
        "agent_version": str(value.get("agent_version", ""))[:40] or None,
        "install_state": str(value.get("install_state", "managed"))[:40],
        "status": "online",
        "last_seen": time.time(),
        "source": str(value.get("source", "agent-registration"))[:80],
    }
    with _LOCK:
        endpoints = list_endpoints()
        endpoints = [item for item in endpoints if item.get("id") != endpoint_id]
        endpoints.append(endpoint)
        _write(_path("endpoints.json"), endpoints[-2_000:])
    return endpoint


def security_groups(endpoints: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    selected = endpoints or list_endpoints()
    names = sorted({str(group) for item in selected for group in item.get("security_groups", [])})
    return [
        {
            "name": name,
            "endpoint_count": sum(name in item.get("security_groups", []) for item in selected),
            "online_count": sum(name in item.get("security_groups", []) and item.get("status") == "online" for item in selected),
            "managed_count": sum(name in item.get("security_groups", []) and bool(item.get("agent_version")) for item in selected),
        }
        for name in names
    ]


def inventory() -> dict[str, Any]:
    endpoints = list_endpoints()
    sessions = _read(_path("discovery-sessions.json"), [])
    deployments = list_deployments()
    return {
        "endpoints": endpoints,
        "security_groups": security_groups(endpoints),
        "summary": {
            "total": len(endpoints),
            "online": sum(item.get("status") == "online" for item in endpoints),
            "managed": sum(bool(item.get("agent_version")) for item in endpoints),
            "groups": len(security_groups(endpoints)),
            "queued_jobs": sum(job.get("status") in {"queued", "deferred"} for deployment in deployments for job in deployment.get("jobs", [])),
        },
        "latest_discovery": sessions[-1] if isinstance(sessions, list) and sessions else None,
    }


def create_discovery_session(value: object | None = None) -> dict[str, Any]:
    if value is not None and not isinstance(value, dict):
        raise ValueError("discovery request must be an object")
    request = value or {}
    started = time.time()
    endpoints = list_endpoints()
    session = {
        "id": uuid.uuid4().hex[:12],
        "created_at": started,
        "completed_at": time.time(),
        "status": "completed",
        "mode": "enrolled-inventory",
        "requested_by": str(request.get("requested_by", "admin-console"))[:120],
        "endpoint_count": len(endpoints),
        "online_count": sum(item.get("status") == "online" for item in endpoints),
        "security_group_count": len(security_groups(endpoints)),
        "sources": ["agent-registration", "demo-inventory"],
    }
    with _LOCK:
        sessions = _read(_path("discovery-sessions.json"), [])
        if not isinstance(sessions, list):
            sessions = []
        sessions.append(session)
        _write(_path("discovery-sessions.json"), sessions[-100:])
    return {**session, "endpoints": endpoints, "security_groups": security_groups(endpoints)}


def _deployment_command(group: str | None, endpoint_ids: list[str], version: str, execute: bool) -> str:
    selector = f"--group {group}" if group else " ".join(f"--endpoint {item}" for item in endpoint_ids)
    suffix = " --execute" if execute else ""
    return f"uig-admin deploy --server http://intentgate.example:8787 {selector} --version {version}{suffix}"


def create_deployment(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("deployment request must be an object")
    group = str(value.get("security_group", "")).strip()[:80] or None
    endpoint_ids_value = value.get("endpoint_ids", [])
    if not isinstance(endpoint_ids_value, list):
        raise ValueError("endpoint_ids must be an array")
    endpoint_ids = sorted({str(item) for item in endpoint_ids_value if _ENDPOINT_ID.fullmatch(str(item))})
    if not group and not endpoint_ids:
        raise ValueError("security_group or endpoint_ids is required")
    version = str(value.get("version", "0.4.0")).strip()
    if not _VERSION.fullmatch(version):
        raise ValueError("version contains unsupported characters")
    execute = bool(value.get("execute", False))
    endpoints = list_endpoints()
    selected = [item for item in endpoints if (group and group in item.get("security_groups", [])) or item.get("id") in endpoint_ids]
    if not selected:
        raise ValueError("selector did not match any enrolled endpoints")
    deployment_id = uuid.uuid4().hex[:12]
    created = time.time()
    jobs = [
        {
            "id": uuid.uuid4().hex[:12],
            "deployment_id": deployment_id,
            "endpoint_id": item["id"],
            "hostname": item["hostname"],
            "status": "planned" if not execute else ("queued" if item.get("status") == "online" else "deferred"),
            "transport": "agent-pull",
            "manifest": {
                "action": "install-or-upgrade-intentgate",
                "package": "user-intent-gate",
                "version": version,
                "restart_service": True,
            },
            "created_at": created,
            "updated_at": created,
        }
        for item in selected
    ]
    deployment = {
        "id": deployment_id,
        "created_at": created,
        "requested_by": str(value.get("requested_by", "admin-console"))[:120],
        "security_group": group,
        "endpoint_ids": [item["id"] for item in selected],
        "version": version,
        "execute": execute,
        "status": "queued" if execute else "planned",
        "matched_endpoints": len(selected),
        "network_command": _deployment_command(group, endpoint_ids or [item["id"] for item in selected], version, execute),
        "jobs": jobs,
    }
    with _LOCK:
        deployments = list_deployments()
        deployments.append(deployment)
        _write(_path("deployments.json"), deployments[-250:])
    return deployment


def list_deployments(limit: int = 50) -> list[dict[str, Any]]:
    value = _read(_path("deployments.json"), [])
    if not isinstance(value, list):
        return []
    return list(reversed([item for item in value if isinstance(item, dict)][-max(1, min(limit, 250)):]))


def next_job(endpoint_id: str) -> dict[str, Any] | None:
    if not _ENDPOINT_ID.fullmatch(endpoint_id):
        raise ValueError("invalid endpoint id")
    for deployment in list_deployments(250):
        for job in deployment.get("jobs", []):
            if job.get("endpoint_id") == endpoint_id and job.get("status") == "queued":
                return job
    return None


def update_job(job_id: str, value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        raise ValueError("job update must be an object")
    status = str(value.get("status", ""))
    if status not in {"acknowledged", "running", "succeeded", "failed"}:
        raise ValueError("status must be acknowledged, running, succeeded, or failed")
    with _LOCK:
        deployments = list(reversed(list_deployments(250)))
        selected = None
        for deployment in deployments:
            for job in deployment.get("jobs", []):
                if job.get("id") == job_id:
                    job["status"] = status
                    job["updated_at"] = time.time()
                    job["detail"] = str(value.get("detail", ""))[:500] or None
                    selected = job
                    break
            statuses = {job.get("status") for job in deployment.get("jobs", [])}
            if statuses and statuses <= {"succeeded"}:
                deployment["status"] = "succeeded"
            elif "failed" in statuses:
                deployment["status"] = "attention-required"
            elif statuses & {"acknowledged", "running"}:
                deployment["status"] = "in-progress"
        if selected is not None:
            _write(_path("deployments.json"), deployments)
        return selected
