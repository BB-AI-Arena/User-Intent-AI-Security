# WAF operations

The Docker deployment places the official [OWASP ModSecurity Core Rule Set (CRS) container](https://github.com/coreruleset/modsecurity-crs-docker) in front of the Intent Gate HTTP API. The backend has no published host port and is reachable only on Docker's internal application network.

## Default policy

| Control | Default |
|---|---|
| Rule engine | Blocking (`On`) |
| CRS release | 4.25 LTS |
| Blocking paranoia | 1 |
| Detection paranoia | 2 |
| Inbound anomaly threshold | 5 |
| Allowed methods | `GET`, `POST` |
| Request content type | `application/json` |
| Maximum request body | 1 MiB |
| Response-body inspection | Disabled |
| Published interface | Loopback only |

Relevant audit events are written as JSON to the container log. Routine access logging is disabled. Request headers and bodies are deliberately excluded because they may contain bearer credentials, commands, identity fields, or security telemetry. A suspicious request URI, query string, and rule-matched fragment can still appear in an audit event and must be handled as sensitive data. Docker log rotation is bounded to five 10 MiB files.

## Start and verify

```bash
docker compose --env-file .env.integrations -f docker-compose.observability.yml up -d --build
curl http://127.0.0.1:8787/healthz
docker compose -f docker-compose.observability.yml logs waf
```

The public API endpoint remains port `8787`; traffic now terminates at the WAF and is proxied internally. Prometheus intentionally scrapes the backend over the private application network.

## Tune safely

Copy `.env.integrations.example` to the ignored `.env.integrations` file. Begin new rules or higher paranoia levels in `DetectionOnly`, observe representative traffic, document false positives, and then switch back to `On`. Do not raise anomaly thresholds as a substitute for a narrow, reviewed rule exclusion.

Webhook payloads often contain attack descriptions or command fragments that resemble real exploits. Test every enabled AV, EDR, and SIEM source against the WAF before enforcing changes. Keep exclusions scoped to the smallest route, field, and rule ID possible.

Set `UIG_BIND_ADDRESS=0.0.0.0` only when the host firewall and an approved TLS ingress restrict access. The bundled HTTP listener is for local evaluation; production deployments should terminate TLS with managed certificates at this WAF or at a trusted upstream load balancer.

## Limitations

A WAF protects the HTTP surface; it does not make the command wrapper non-bypassable, authenticate read-only endpoints, prevent host-level Docker access, or replace rate limiting and identity-aware access control. Treat its logs as sensitive security records and forward them through an approved pipeline when durable retention is required.

For rule concepts and safe tuning practices, use the [official OWASP CRS documentation](https://coreruleset.org/docs/).
