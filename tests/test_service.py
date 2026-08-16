import json
import os
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from intentgate.service import Handler


class ServiceTests(unittest.TestCase):
    def _request(self, url, token, method="GET", body=None):
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method=method,
        )
        return urllib.request.urlopen(request, timeout=2)

    def test_ingest_posture_and_metrics(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"UIG_STATE_DIR": directory, "UIG_INGEST_TOKEN": "synthetic-test-token"},
        ):
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                payload = json.dumps({
                    "source": "smoke-siem",
                    "event_id": "event-1",
                    "score": 88,
                    "confidence": 1,
                    "ttl_seconds": 60,
                    "detail": "test alert",
                }).encode("utf-8")
                request = urllib.request.Request(
                    f"{base}/v1/signals",
                    data=payload,
                    headers={"Authorization": "Bearer synthetic-test-token", "Content-Type": "application/json"},
                    method="POST",
                )
                accepted = json.loads(urllib.request.urlopen(request, timeout=2).read())
                posture = json.loads(urllib.request.urlopen(f"{base}/v1/posture", timeout=2).read())
                metrics = urllib.request.urlopen(f"{base}/metrics", timeout=2).read().decode("utf-8")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
        self.assertEqual(accepted["accepted"], 1)
        self.assertEqual(posture["risk_score"], 88)
        self.assertIn("intentgate_security_posture 88", metrics)

    def test_operator_console_assessment_review_policy_and_audit(self):
        token = "synthetic-console-token"
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"UIG_STATE_DIR": directory, "UIG_INGEST_TOKEN": token, "UIG_MODEL_PROVIDER": "disabled"}
        ), patch("intentgate.service.HISTORY_FILE", Path(directory, "history.jsonl")), patch(
            "intentgate.context.HISTORY_FILE", Path(directory, "history.jsonl")
        ), patch("intentgate.audit.HISTORY_FILE", Path(directory, "history.jsonl")):
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                console = urllib.request.urlopen(f"{base}/", timeout=2).read().decode("utf-8")
                assessment = json.loads(self._request(
                    f"{base}/v1/assess", token, "POST",
                    {"argv": ["git", "push"], "purpose": "publish reviewed changes", "cwd": directory,
                     "execution_context": {"user_name": "casey", "endpoint_name": "DEV-WS-042"}},
                ).read())
                reviews = json.loads(self._request(f"{base}/v1/reviews", token).read())
                review_id = assessment["review"]["id"]
                approved = json.loads(self._request(
                    f"{base}/v1/reviews/{review_id}", token, "POST", {"status": "approved"}
                ).read())
                policy = json.loads(self._request(
                    f"{base}/v1/policy", token, "POST",
                    {"name": "poc-policy", "review_threshold": 35, "block_threshold": 80},
                ).read())
                model = json.loads(self._request(f"{base}/v1/model", token).read())
                controls = json.loads(self._request(
                    f"{base}/v1/trust-controls", token, "POST",
                    {
                        "zero_trust": {"enforcement_mode": "enforce", "step_up_threshold": 55, "session_ttl_minutes": 20},
                        "microsegmentation": {"default_action": "deny", "enabled_zones": ["edge", "application"], "allowed_flows": ["edge>application"]},
                    },
                ).read())
                stepped_up = json.loads(self._request(
                    f"{base}/v1/assess", token, "POST",
                    {"argv": ["git", "status"], "cwd": directory},
                ).read())
                model_assessment = json.loads(self._request(
                    f"{base}/v1/model-assess", token, "POST",
                    {"argv": ["git", "push"], "purpose": "publish reviewed changes", "cwd": directory},
                ).read())
                audit = json.loads(self._request(f"{base}/v1/audit", token).read())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
        self.assertIn("Operator Console", console)
        self.assertEqual(assessment["decision"], "review")
        self.assertEqual(assessment["execution"], "not_requested")
        self.assertNotIn("root-risk-amplifier", {item["name"] for item in assessment["signals"]})
        self.assertEqual(len(reviews["reviews"]), 1)
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(policy["name"], "poc-policy")
        self.assertEqual(policy["version"], 2)
        self.assertEqual(model["status"], "disabled")
        self.assertEqual(controls["version"], 2)
        self.assertEqual(controls["zero_trust"]["enforcement_mode"], "enforce")
        self.assertEqual(controls["microsegmentation"]["allowed_flows"], ["edge>application"])
        self.assertEqual(stepped_up["decision"], "review")
        self.assertIn("zero-trust-step-up", {item["name"] for item in stepped_up["signals"]})
        self.assertEqual(model_assessment["status"], "disabled")
        self.assertEqual(model_assessment["deterministic"]["decision"], "review")
        self.assertEqual(len(audit["events"]), 2)
        detailed = next(item for item in audit["events"] if item["command"] == "git push")
        self.assertEqual(detailed["user_name"], "casey")
        self.assertEqual(detailed["endpoint_name"], "DEV-WS-042")
        self.assertTrue(detailed["signal_details"])


if __name__ == "__main__":
    unittest.main()
