from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import shlex
import socket
import time
from dataclasses import replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .audit import record
from .behavior import assess_anomaly
from .catalog import DESTRUCTIVE_ACTIONS
from .context import HISTORY_FILE, collect_context
from .deployments import (
    create_deployment,
    create_discovery_session,
    inventory,
    list_deployments,
    next_job,
    register_endpoint,
    update_job,
)
from .engine import assess
from .integrations import ingest, read_posture, source_postures
from .model_advisory import model_status, request_model_advisory
from .models import Decision
from .policy import load_policy, save_policy
from .reporting import pending_report_count
from .reviews import create_review, decide_review, list_reviews
from .security_policies import list_security_policies, save_security_policy
from .trust_controls import apply_zero_trust, load_trust_controls, save_trust_controls


STARTED_AT = time.time()


def _assess_payload(body: object):
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")
    raw_command = str(body.get("command", "")).strip()
    argv_value = body.get("argv")
    if isinstance(argv_value, list) and all(isinstance(item, str) for item in argv_value):
        argv = argv_value
    elif raw_command:
        argv = shlex.split(raw_command, posix=os.name != "nt")
    else:
        raise ValueError("command or argv is required")
    if not argv:
        raise ValueError("command cannot be empty")
    cwd = Path(str(body.get("cwd") or os.getcwd())).expanduser().resolve()
    if not cwd.is_dir():
        raise ValueError("cwd must be an existing directory")
    purpose = str(body.get("purpose", "")).strip()[:500] or None
    context = collect_context(argv, purpose=purpose, cwd=str(cwd))
    execution_context = body.get("execution_context")
    if execution_context is not None and not isinstance(execution_context, dict):
        raise ValueError("execution_context must be an object")
    execution_context = execution_context or {}
    user_name = str(execution_context.get("user_name", "console-operator"))[:120]
    anomaly = assess_anomaly(context.command, user_name=user_name)
    context = replace(
        context,
        user_name=user_name,
        endpoint_name=str(execution_context.get("endpoint_name") or socket.gethostname())[:160],
        is_root=bool(execution_context.get("is_root", False)),
        is_admin=bool(execution_context.get("is_admin", False)),
        privilege_level=str(execution_context.get("privilege_level", "standard"))[:80],
        anomaly_score=int(anomaly.get("score", 0)),
        anomaly_details=tuple(str(item) for item in anomaly.get("details", ())),
    )
    return context, apply_zero_trust(context, assess(context))


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
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _asset(self, filename: str, content_type: str) -> None:
        try:
            payload = resources.files("intentgate").joinpath("web", filename).read_bytes()
        except (FileNotFoundError, OSError):
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:",
        )
        self.end_headers()
        self.wfile.write(payload)

    def _body(self) -> object:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_048_576:
            raise ValueError("payload exceeds 1 MiB")
        return json.loads(self.rfile.read(length))

    def _audit_events(self, limit: int) -> list[dict[str, object]]:
        try:
            lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()[-limit:]
        except OSError:
            return []
        events = []
        for line in reversed(lines):
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    events.append(item)
            except json.JSONDecodeError:
                continue
        return events

    def _authorized(self) -> bool:
        expected = os.environ.get("UIG_INGEST_TOKEN", "")
        if not expected:
            return self.client_address[0] in {"127.0.0.1", "::1"}
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return hmac.compare_digest(expected, supplied)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/console"}:
            self._asset("index.html", "text/html; charset=utf-8")
            return
        if parsed.path == "/console.css":
            self._asset("console.css", "text/css; charset=utf-8")
            return
        if parsed.path == "/console.js":
            self._asset("console.js", "text/javascript; charset=utf-8")
            return
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
        protected = {
            "/v1/audit", "/v1/reviews", "/v1/policy", "/v1/model", "/v1/trust-controls",
            "/v1/endpoints", "/v1/deployments", "/v1/deployment-jobs/next", "/v1/security-policies",
        }
        if parsed.path in protected and not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if parsed.path == "/v1/audit":
            query = parse_qs(parsed.query)
            try:
                limit = max(1, min(int(query.get("limit", ["100"])[0]), 500))
            except ValueError:
                limit = 100
            self._json(HTTPStatus.OK, {"events": self._audit_events(limit)})
            return
        if parsed.path == "/v1/reviews":
            self._json(HTTPStatus.OK, {"reviews": list_reviews()})
            return
        if parsed.path == "/v1/policy":
            policy = load_policy()
            policy["catalog"] = [
                {
                    "identifier": item.identifier,
                    "category": item.category,
                    "score": item.score,
                    "description": item.description,
                    "platforms": item.platforms,
                }
                for item in DESTRUCTIVE_ACTIONS
            ]
            self._json(HTTPStatus.OK, policy)
            return
        if parsed.path == "/v1/model":
            self._json(HTTPStatus.OK, model_status())
            return
        if parsed.path == "/v1/trust-controls":
            self._json(HTTPStatus.OK, load_trust_controls())
            return
        if parsed.path == "/v1/security-policies":
            self._json(HTTPStatus.OK, list_security_policies())
            return
        if parsed.path == "/v1/endpoints":
            self._json(HTTPStatus.OK, inventory())
            return
        if parsed.path == "/v1/deployments":
            query = parse_qs(parsed.query)
            try:
                limit = max(1, min(int(query.get("limit", ["50"])[0]), 250))
            except ValueError:
                limit = 50
            self._json(HTTPStatus.OK, {"deployments": list_deployments(limit)})
            return
        if parsed.path == "/v1/deployment-jobs/next":
            endpoint_id = parse_qs(parsed.query).get("endpoint_id", [""])[0]
            self._json(HTTPStatus.OK, {"job": next_job(endpoint_id)})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        known = parsed.path in {
            "/v1/signals", "/v1/events", "/v1/assess", "/v1/model-assess", "/v1/policy",
            "/v1/trust-controls", "/v1/endpoints/register", "/v1/discovery-sessions", "/v1/deployments",
            "/v1/security-policies",
        }
        review_match = re.fullmatch(r"/v1/reviews/([a-f0-9]{12})", parsed.path)
        job_match = re.fullmatch(r"/v1/deployment-jobs/([a-f0-9]{12})", parsed.path)
        if not known and review_match is None and job_match is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            body = self._body()
            if parsed.path == "/v1/assess":
                context, result = _assess_payload(body)
                review = create_review(context, result) if result.decision is Decision.REVIEW else None
                record(context, result, executed=False)
                response = result.to_dict()
                response["review"] = review
                response["execution"] = "not_requested"
                self._json(HTTPStatus.OK, response)
                return
            if parsed.path == "/v1/model-assess":
                context, result = _assess_payload(body)
                response = request_model_advisory(context, result)
                response["deterministic"] = {
                    "decision": result.decision.value,
                    "risk_score": result.risk_score,
                    "policy_name": result.policy_name,
                    "policy_version": result.policy_version,
                }
                self._json(HTTPStatus.OK, response)
                return
            if parsed.path == "/v1/policy":
                policy = save_policy(body)
                self._json(HTTPStatus.OK, policy)
                return
            if parsed.path == "/v1/trust-controls":
                controls = save_trust_controls(body)
                self._json(HTTPStatus.OK, controls)
                return
            if parsed.path == "/v1/security-policies":
                policy = save_security_policy(body)
                self._json(HTTPStatus.OK, policy)
                return
            if parsed.path == "/v1/endpoints/register":
                endpoint = register_endpoint(body)
                self._json(HTTPStatus.OK, endpoint)
                return
            if parsed.path == "/v1/discovery-sessions":
                session = create_discovery_session(body)
                self._json(HTTPStatus.OK, session)
                return
            if parsed.path == "/v1/deployments":
                deployment = create_deployment(body)
                self._json(HTTPStatus.ACCEPTED, deployment)
                return
            if review_match is not None:
                if not isinstance(body, dict):
                    raise ValueError("payload must be an object")
                selected = decide_review(
                    review_match.group(1), str(body.get("status", "")), str(body.get("note", "")) or None
                )
                if selected is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "review not found"})
                else:
                    self._json(HTTPStatus.OK, selected)
                return
            if job_match is not None:
                selected = update_job(job_match.group(1), body)
                if selected is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "deployment job not found"})
                else:
                    self._json(HTTPStatus.OK, selected)
                return
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
