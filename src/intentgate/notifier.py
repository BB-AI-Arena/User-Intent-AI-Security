from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any

from .reporting import reports_dir


def _message(report: dict[str, Any]) -> str:
    subject = report.get("subject", {})
    signals = ", ".join(item.get("name", "unknown") for item in report.get("signals", [])[:8])
    return (
        f"Intent Gate risk report: {report.get('decision', 'unknown').upper()} "
        f"risk={report.get('risk_score', 0)}/100; user={subject.get('user', 'unknown')} "
        f"privilege={subject.get('privilege_level', 'unknown')}; command={report.get('command', '')}; "
        f"signals={signals}; report={report.get('report_id', '')}"
    )


def _payload(report: dict[str, Any], style: str) -> dict[str, Any]:
    message = _message(report)
    if style == "slack":
        return {"text": message}
    if style == "teams":
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {"type": "AdaptiveCard", "version": "1.4", "body": [{"type": "TextBlock", "wrap": True, "text": message}]}}]}
    return {"event": "intentgate.manager_risk_report", "summary": message, "report": report}


def deliver(path: Path, url: str, token: str | None, style: str) -> None:
    report = json.loads(path.read_text(encoding="utf-8"))
    body = json.dumps(_payload(report, style)).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "IntentGate/0.3"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError(f"manager webhook returned HTTP {response.status}")
    path.unlink()


def run_once(url: str, token: str | None, style: str) -> tuple[int, int]:
    sent = failed = 0
    for path in sorted(reports_dir().glob("*.json"))[:100]:
        try:
            deliver(path, url, token, style)
            sent += 1
        except Exception as exc:
            failed += 1
            print(f"{path.name}: {type(exc).__name__}: {exc}")
    return sent, failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deliver queued Intent Gate risk reports to a manager webhook")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--style", choices=("generic", "slack", "teams"), default=os.environ.get("UIG_MANAGER_WEBHOOK_STYLE", "generic"))
    args = parser.parse_args(argv)
    url = os.environ.get("UIG_MANAGER_WEBHOOK_URL", "")
    if not url:
        print("UIG_MANAGER_WEBHOOK_URL is required; queued reports were not sent.")
        return 2
    token = os.environ.get("UIG_MANAGER_WEBHOOK_TOKEN")
    while True:
        sent, failed = run_once(url, token, args.style)
        print(f"manager notifier: sent={sent} failed={failed}")
        if args.once:
            return 0 if failed == 0 else 1
        time.sleep(max(1.0, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
