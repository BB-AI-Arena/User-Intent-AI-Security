import json
import os
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from intentgate.service import Handler


class ServiceTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
