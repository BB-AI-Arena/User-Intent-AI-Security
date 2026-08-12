from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .context import HISTORY_FILE
from .integrations import ingest, read_posture, source_postures
from .reporting import pending_report_count


STARTED_AT = time.time()


def _audit_metrics() -> tuple[dict[str, int], float, int]:
    counts = {"allow": 0, "review": 0, "block": 0}
    latencies: list[float] = []
    try:
        lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()[-5000:]
    except OSError:
        return counts, 0.0, 0
    for line in lines:
        try:
            item = json.loads(line)
            decision = str(item.get("decision", ""))
            if decision in counts:
                counts[decision] += 1
            if "latency_ms" in item:
                latencies.append(float(item["latency_ms"]))
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    average = sum(latencies) / len(latencies) if latencies else 0.0
    return counts, average, len(lines)


def prometheus_metrics() -> str:
    posture = read_posture()
    counts, average_latency, events = _audit_metrics()
    lines = [
        "# HELP intentgate_security_posture Current aggregate external security risk score.",
        "# TYPE intentgate_security_posture gauge",
        f"intentgate_security_posture {posture['risk_score']}",
        "# HELP intentgate_active_external_signals Number of non-expired external security signals.",
        "# TYPE intentgate_active_external_signals gauge",
        f"intentgate_active_external_signals {posture['active_signals']}",
        "# HELP intentgate_decisions_total Gate decisions observed in the local audit history.",
        "# TYPE intentgate_decisions_total counter",
    ]
    for decision, count in counts.items():
        lines.append(f'intentgate_decisions_total{{decision="{decision}"}} {count}')
    lines.extend([
        "# HELP intentgate_audit_events Number of audit events currently included.",
        "# TYPE intentgate_audit_events gauge",
        f"intentgate_audit_events {events}",
        "# HELP intentgate_decision_latency_ms Average recorded policy-engine latency.",
        "# TYPE intentgate_decision_latency_ms gauge",
        f"intentgate_decision_latency_ms {average_latency:.6f}",
        "# HELP intentgate_uptime_seconds Integration service uptime.",
        "# TYPE intentgate_uptime_seconds gauge",
        f"intentgate_uptime_seconds {time.time() - STARTED_AT:.3f}",
        "# HELP intentgate_pending_manager_reports Queued risk reports awaiting delivery.",
        "# TYPE intentgate_pending_manager_reports gauge",
        f"intentgate_pending_manager_reports {pending_report_count()}",
        "# HELP intentgate_source_risk External security risk by normalized source.",
        "# TYPE intentgate_source_risk gauge",
    ])
    for source, score in source_postures().items():
        safe = re.sub(r"[^a-zA-Z0-9_.:-]", "_", source)
        lines.append(f'intentgate_source_risk{{source="{safe}"}} {score}')
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    server_version = "IntentGate/0.1"

    def _json(self, status: int, body: object) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self) -> bool:
        expected = os.environ.get("UIG_INGEST_TOKEN", "")
        if not expected:
            return self.client_address[0] in {"127.0.0.1", "::1"}
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return hmac.compare_digest(expected, supplied)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        if parsed.path == "/v1/posture":
            query = parse_qs(parsed.query)
            self._json(HTTPStatus.OK, read_posture(
                device=query.get("device", [None])[0],
                user=query.get("user", [None])[0],
                project=query.get("project", [None])[0],
            ))
            return
        if parsed.path == "/metrics":
            payload = prometheus_metrics().encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path not in {"/v1/signals", "/v1/events"}:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 1_048_576)
            body = json.loads(self.rfile.read(length))
            items = body if isinstance(body, list) else [body]
            if not all(isinstance(item, dict) for item in items):
                raise ValueError("payload must be an object or list of objects")
            accepted = ingest(items)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        self._json(HTTPStatus.ACCEPTED, {"accepted": accepted})

    def log_message(self, format: str, *args) -> None:
        if os.environ.get("UIG_HTTP_LOG", "") == "1":
            super().log_message(format, *args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Intent Gate integration and metrics service")
    parser.add_argument("--host", default=os.environ.get("UIG_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("UIG_PORT", "8787")))
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Intent Gate service listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
