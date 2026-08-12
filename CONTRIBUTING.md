# Contributing

Thank you for helping improve User Intent AI Security.

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Linux and macOS users can substitute `.venv/bin/python`.

## Pull requests

1. Open an issue first for major policy, architecture, telemetry, or privacy changes.
2. Keep each pull request focused on one coherent outcome.
3. Add tests for new rules, integrations, redaction behavior, and decision changes.
4. Explain false-positive and false-negative tradeoffs for security detections.
5. Never commit real credentials, customer events, employee command history, or private manager reports.
6. Run the test suite, bytecode compilation, and Compose validation before requesting review.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q src tests
docker compose -f docker-compose.observability.yml config --quiet
```

## Detection contributions

New destructive-action patterns should include:

- The platforms and command families affected
- A concise risk category and explanation
- A conservative score justified by likely impact
- Positive and negative tests
- Consideration of quoting, aliases, mixed case, and benign administrative usage

Avoid broad patterns that classify ordinary read-only commands as destructive.

## Integration contributions

Use the normalized signal model. Keep credentials in environment variables, bound network operations, use event IDs for deduplication, define TTL behavior, and document the vendor API version used.

