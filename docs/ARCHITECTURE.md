# Architecture

## Design goal

The command path should remain fast enough that users do not notice the gate during ordinary work. The architecture separates synchronous policy evaluation from every operation that can block on a model, vendor API, network, or notification service.

## Components

| Component | Responsibility | Execution path |
|---|---|---|
| `context.py` | Collect bounded local user, Git, project, and cached posture context | Synchronous |
| `catalog.py` / `rules.py` | Classify behavior and calculate risk signals | Synchronous |
| `engine.py` | Aggregate signals into `ALLOW`, `REVIEW`, or `BLOCK` | Synchronous |
| `behavior.py` | Compare a command family with recent per-user history | Synchronous local read |
| `provenance.py` | Scan source health and provenance indicators | Asynchronous/manual |
| `collector.py` | Poll AV, EDR, and SIEM APIs | Background |
| `integrations.py` | Normalize, scope, deduplicate, expire, and correlate signals | Background writes; cached reads |
| `reporting.py` | Redact and queue high-risk reports | Local append after decision |
| `notifier.py` | Deliver reports to approved webhooks | Background |
| `service.py` | Ingest signals and expose posture and Prometheus metrics | Background |
| Operator console | Assess commands, record review decisions, inspect audit history, and version thresholds | Browser UI; assessment-only |
| `model_advisory.py` | Request and normalize an independent OpenAI, OpenAI-compatible, or gateway recommendation | Asynchronous console path; never authoritative |
| OWASP CRS WAF | Inspect, constrain, and proxy all host-originated API traffic | Network edge |

## Data flow

External signals receive a score, confidence, scope, and TTL. The correlation layer takes the highest effective signal and adds bounded corroboration from other sources. The gate reads only non-expired local state.

The Docker deployment publishes only the OWASP Core Rule Set WAF. The Intent Gate service is isolated on an internal application network; Prometheus reaches it there for scraping, while external webhook and API clients traverse the WAF. See [WAF Operations](WAF.md).

The operator console is served by the same service and uses bearer-authenticated local APIs. It does not own process creation: command assessments are recorded with `executed=false`, and review approvals change only the review record. This keeps a browser compromise from becoming a direct command-execution primitive.

Audit and report files are local JSON/JSONL in `UIG_STATE_DIR`. The PowerShell helper defaults this to `.intentgate-state` in the project so the host CLI and Docker observability services share the same state.

## Latency model

No external API is called during a command decision. The development benchmark for context collection and scoring is approximately 0.53 ms in-process. Python process startup is separate; production deployments should use a persistent broker or daemon.

## Enforcement boundary

The CLI wrapper demonstrates policy behavior but is bypassable. Production integrations should place the engine inside the agent tool broker, shell host, endpoint service, or privileged API that owns process creation.

