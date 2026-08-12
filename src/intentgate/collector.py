from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

from .integrations import ingest


DEFAULT_SEVERITY = {
    "informational": 5,
    "info": 5,
    "low": 25,
    "medium": 50,
    "moderate": 50,
    "high": 75,
    "critical": 95,
    "severe": 95,
}


def _path(value: Any, dotted: str | None, default: Any = None) -> Any:
    if not dotted:
        return value
    current = value
    for part in dotted.split("."):
        if isinstance(current, dict):
            current = current.get(part, default)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return default
    return current


def _headers(config: dict[str, Any]) -> dict[str, str]:
    headers = {str(k): str(v) for k, v in config.get("headers", {}).items()}
    if env_name := config.get("bearer_token_env"):
        token = os.environ.get(str(env_name), "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    if env_name := config.get("api_token_env"):
        token = os.environ.get(str(env_name), "")
        if token:
            prefix = str(config.get("api_token_prefix", ""))
            headers[str(config.get("api_token_header", "Authorization"))] = f"{prefix}{token}"
    return headers


def poll_integration(config: dict[str, Any]) -> int:
    if config.get("kind") == "windows_defender":
        return poll_windows_defender(config)
    body = config.get("body")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = _headers(config)
    if data is not None:
        headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        str(config["url"]),
        data=data,
        headers=headers,
        method=str(config.get("method", "POST" if data is not None else "GET")),
    )
    with urllib.request.urlopen(request, timeout=float(config.get("timeout_seconds", 5))) as response:
        raw = response.read(4_194_304).decode("utf-8")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
        document = [row.get("result", row) if isinstance(row, dict) else row for row in rows]
    records = _path(document, config.get("records_path"), document)
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        raise ValueError(f"{config.get('name', 'integration')}: records_path did not resolve to a list")

    mapping = {**DEFAULT_SEVERITY, **{str(k).lower(): int(v) for k, v in config.get("severity_map", {}).items()}}
    payloads: list[dict[str, Any]] = []
    for record in records[: int(config.get("max_records", 200))]:
        if not isinstance(record, dict):
            continue
        excluded = False
        for field, values in config.get("exclude_values", {}).items():
            actual = str(_path(record, str(field), "")).lower()
            if actual in {str(value).lower() for value in values}:
                excluded = True
                break
        if excluded:
            continue
        raw_score = _path(record, config.get("score_path"))
        severity = str(_path(record, config.get("severity_path"), "")).lower()
        score = int(float(raw_score)) if raw_score is not None else mapping.get(severity, 0)
        scope = {str(k): str(_path(record, str(v), "")) for k, v in config.get("scope_paths", {}).items()}
        scope = {key: value for key, value in scope.items() if value}
        payloads.append({
            "source": config.get("name", "unknown"),
            "event_id": _path(record, config.get("id_path")),
            "score": score,
            "confidence": float(config.get("confidence", 0.9)),
            "detail": _path(record, config.get("detail_path"), severity or "external security event"),
            "ttl_seconds": int(config.get("ttl_seconds", 300)),
            "scope": scope,
        })
    return ingest(payloads) if payloads else 0


def poll_windows_defender(config: dict[str, Any]) -> int:
    script = (
        "$status=Get-MpComputerStatus;"
        "$threats=@(Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 100);"
        "[pscustomobject]@{healthy=($status.AntivirusEnabled -and $status.RealTimeProtectionEnabled);"
        "age=[math]::Round(((Get-Date)-$status.AntivirusSignatureLastUpdated).TotalHours,1);threats=$threats}"
        "| ConvertTo-Json -Depth 5 -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=float(config.get("timeout_seconds", 8)),
        check=True,
    )
    document = json.loads(result.stdout)
    payloads: list[dict[str, Any]] = []
    if not document.get("healthy", False):
        payloads.append({
            "source": config.get("name", "windows-defender"),
            "event_id": "protection-disabled",
            "score": 85,
            "confidence": 1.0,
            "detail": "Microsoft Defender antivirus or real-time protection is disabled.",
            "ttl_seconds": int(config.get("ttl_seconds", 120)),
        })
    if float(document.get("age", 0)) > 48:
        payloads.append({
            "source": config.get("name", "windows-defender"),
            "event_id": "stale-signatures",
            "score": 55,
            "confidence": 0.95,
            "detail": f"Microsoft Defender signatures are {document['age']} hours old.",
            "ttl_seconds": int(config.get("ttl_seconds", 120)),
        })
    threats = document.get("threats") or []
    if isinstance(threats, dict):
        threats = [threats]
    for index, threat in enumerate(threats):
        payloads.append({
            "source": config.get("name", "windows-defender"),
            "event_id": threat.get("ThreatID") or f"threat-{index}",
            "score": 95,
            "confidence": 1.0,
            "detail": str(threat.get("Resources") or "Microsoft Defender reported an active/recent threat."),
            "ttl_seconds": int(config.get("threat_ttl_seconds", 3600)),
        })
    return ingest(payloads) if payloads else 0


def load_config(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    integrations = document.get("integrations", [])
    if not isinstance(integrations, list):
        raise ValueError("integrations must be a list")
    return [item for item in integrations if isinstance(item, dict) and item.get("enabled", True)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Poll AV/EDR/SIEM JSON APIs into Intent Gate")
    parser.add_argument("config", type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=30.0)
    args = parser.parse_args(argv)
    while True:
        for integration in load_config(args.config):
            try:
                accepted = poll_integration(integration)
                print(f"{integration.get('name', 'integration')}: accepted {accepted} signal(s)")
            except Exception as exc:  # collector failures must not stop command execution
                print(f"{integration.get('name', 'integration')}: {type(exc).__name__}: {exc}")
        if args.once:
            return 0
        time.sleep(max(1.0, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
