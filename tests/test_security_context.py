import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from intentgate.behavior import assess_anomaly
from intentgate.catalog import match_destructive_actions
from intentgate.engine import assess
from intentgate.models import CommandContext, Decision
from intentgate.reporting import queue_manager_report, redact_command
from intentgate.notifier import run_once


class SecurityContextTests(unittest.TestCase):
    def test_linux_and_windows_destructive_catalog(self):
        linux = {item.identifier for item in match_destructive_actions("rm -rf /srv/app")}
        windows = {item.identifier for item in match_destructive_actions("vssadmin delete shadows /all")}
        self.assertIn("recursive-delete-unix", linux)
        self.assertIn("shadow-copy-delete", windows)

    def test_root_amplifies_risky_command(self):
        context = CommandContext(
            cwd="/srv/app", command="systemctl stop auditd", argv=("systemctl", "stop", "auditd"),
            user_name="root", is_root=True, is_admin=True, privilege_level="root",
        )
        result = assess(context)
        names = {signal.name for signal in result.signals}
        self.assertIs(result.decision, Decision.BLOCK)
        self.assertIn("root-risk-amplifier", names)
        self.assertIn("destructive-action", names)

    def test_behavioral_baseline_finds_unseen_family(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"UIG_STATE_DIR": directory}):
            history = Path(directory, "history.jsonl")
            rows = [{"command": "git status", "user_name": "example-user"} for _ in range(25)]
            history.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
            result = assess_anomaly("terraform destroy", user_name="example-user")
        self.assertGreaterEqual(result["score"], 20)

    def test_manager_report_is_queued_and_secrets_are_redacted(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"UIG_STATE_DIR": directory}):
            context = CommandContext(
                cwd=".", command="deploy --token synthetic-secret", argv=("deploy",), user_name="example-user",
                is_admin=True, privilege_level="administrator",
            )
            result = assess(CommandContext(cwd=".", command="format C:", argv=("format", "C:"), user_name="example-user"))
            path = queue_manager_report(context, result, executed=False, exit_code=None)
            self.assertIsNotNone(path)
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotIn("synthetic-secret", report["command"])
        self.assertIn("[REDACTED]", report["command"])

    def test_redacts_url_credentials(self):
        value = redact_command("curl https://example-user:synthetic-password@example.invalid/api")
        self.assertNotIn("synthetic-password", value)

    def test_notifier_delivers_and_removes_report(self):
        received = []

        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(204)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"UIG_STATE_DIR": directory}):
            context = CommandContext(cwd=".", command="format C:", argv=("format", "C:"), user_name="example-user")
            result = assess(context)
            queued = queue_manager_report(context, result, executed=False, exit_code=None)
            server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                sent, failed = run_once(f"http://127.0.0.1:{server.server_port}", None, "generic")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            self.assertEqual((sent, failed), (1, 0))
            self.assertFalse(queued.exists())
        self.assertEqual(received[0]["event"], "intentgate.manager_risk_report")


if __name__ == "__main__":
    unittest.main()
