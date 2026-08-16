import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from intentgate.engine import assess
from intentgate.model_advisory import model_status, request_model_advisory
from intentgate.models import CommandContext


class ModelAdvisoryTests(unittest.TestCase):
    def test_disabled_provider_is_explicit(self):
        with patch.dict(os.environ, {"UIG_MODEL_PROVIDER": "disabled"}):
            self.assertEqual(model_status()["status"], "disabled")

    def test_demo_provider_returns_labeled_structured_advisory(self):
        with patch.dict(os.environ, {"UIG_MODEL_PROVIDER": "demo", "UIG_MODEL_NAME": "intent-advisor-demo"}):
            context = CommandContext(cwd=".", command="git status", argv=("git", "status"), purpose="inspect repository")
            result = request_model_advisory(context, assess(context))
            status = model_status()
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["simulation"])
        self.assertEqual(result["advisory"]["recommended_decision"], "allow")
        self.assertEqual(status["status"], "configured")

    def test_webhook_provider_normalizes_and_redacts(self):
        received = []

        class Advisor(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                body = json.dumps({
                    "recommended_decision": "review",
                    "risk_score": 62,
                    "confidence": 0.88,
                    "intent_alignment": "unclear",
                    "summary": "The action has an external side effect and needs confirmation.",
                    "reasons": ["The declared purpose does not identify the target environment."],
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Advisor)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict(os.environ, {
                "UIG_MODEL_PROVIDER": "webhook",
                "UIG_MODEL_BASE_URL": f"http://127.0.0.1:{server.server_port}/assess",
                "UIG_MODEL_NAME": "synthetic-advisor",
            }):
                context = CommandContext(
                    cwd=".", command="deploy --token synthetic-secret", argv=("deploy",), purpose="release application"
                )
                advisory = request_model_advisory(context, assess(context))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(advisory["status"], "ready")
        self.assertEqual(advisory["advisory"]["recommended_decision"], "review")
        serialized = json.dumps(received)
        self.assertNotIn("synthetic-secret", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_openai_responses_adapter_uses_structured_output(self):
        received = []

        class ResponsesAPI(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append({
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "body": json.loads(self.rfile.read(int(self.headers["Content-Length"]))),
                })
                advisory = {
                    "recommended_decision": "allow",
                    "risk_score": 12,
                    "confidence": 0.93,
                    "intent_alignment": "matched",
                    "summary": "The read-only action matches the stated inspection task.",
                    "reasons": ["The command is read-only."],
                }
                body = json.dumps({
                    "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps(advisory)}]}]
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), ResponsesAPI)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict(os.environ, {
                "UIG_MODEL_PROVIDER": "openai",
                "UIG_MODEL_BASE_URL": f"http://127.0.0.1:{server.server_port}/v1",
                "UIG_MODEL_API_KEY": "synthetic-api-key",
                "UIG_MODEL_NAME": "synthetic-openai-model",
            }):
                context = CommandContext(cwd=".", command="git status", argv=("git", "status"), purpose="inspect git status")
                result = request_model_advisory(context, assess(context))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["advisory"]["recommended_decision"], "allow")
        self.assertEqual(received[0]["path"], "/v1/responses")
        self.assertEqual(received[0]["authorization"], "Bearer synthetic-api-key")
        self.assertEqual(received[0]["body"]["text"]["format"]["type"], "json_schema")


if __name__ == "__main__":
    unittest.main()
