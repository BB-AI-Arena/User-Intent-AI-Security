# Security Integration Guide

## Normalized signal contract

Send a JSON object or array to `POST /v1/signals`:

```json
{
  "source": "security-product",
  "event_id": "stable-alert-id",
  "score": 85,
  "confidence": 0.9,
  "ttl_seconds": 300,
  "detail": "Short operator-readable explanation",
  "scope": {
    "device": "HOST-01",
    "user": "example-user",
    "project": "/example/project"
  }
}
```

`score` is clamped to 0–100, `confidence` to 0–1, and TTL to one second through seven days. Scope keys are optional. Events are deduplicated by source and event ID.

## Authentication

Set `UIG_INGEST_TOKEN` and include:

```text
Authorization: Bearer <token>
```

Without a configured token, ingestion is accepted only from loopback addresses. Production deployments should use TLS and network-level access controls as well.

## Collector configuration

Copy `config/integrations.example.json` to `config/integrations.json`, enable only required sources, and provide credentials through environment variables. Never store API credentials in the JSON file.

```powershell
uig-collector config\integrations.json --once
uig-collector config\integrations.json --interval 30
```

Templates are starting points. Verify endpoints, authorization flows, response fields, severity mappings, filters, pagination, and rate limits against the exact tenant and product version before enforcement.

## Correlation

The highest confidence-weighted active signal forms the base posture. Additional independent signals add bounded corroboration. Expired signals stop contributing. The POC currently fails open when feeds are absent or stale; production policy should make feed health explicit.
