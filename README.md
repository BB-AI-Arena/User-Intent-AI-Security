<div align="center">
  <img src="docs/assets/hero.svg" alt="User Intent AI Security" width="100%" />
</div>

<div align="center">

[![CI](https://github.com/BB-AI-Arena/User-Intent-AI-Security/actions/workflows/ci.yml/badge.svg)](https://github.com/BB-AI-Arena/User-Intent-AI-Security/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
[![Status: POC](https://img.shields.io/badge/status-proof%20of%20concept-f59e0b)](#project-status)
[![Docker](https://img.shields.io/badge/observability-Docker%20Compose-2496ED?logo=docker&logoColor=white)](docker-compose.observability.yml)
[![WAF](https://img.shields.io/badge/WAF-OWASP%20CRS-000000?logo=owasp&logoColor=white)](docs/WAF.md)
[![Terraform](https://img.shields.io/badge/IaC-Terraform-844FBA?logo=terraform&logoColor=white)](deploy/terraform)
[![Ansible](https://img.shields.io/badge/automation-Ansible-EE0000?logo=ansible&logoColor=white)](deploy/ansible)

**A context-aware command execution gate that asks one critical question before code runs: _does this action match the user's intent?_**

[Why it matters](#why-this-project-matters) · [Capabilities](#what-the-project-can-do) · [Live POC demo](#run-the-full-poc-demo) · [Use cases](#where-it-can-be-used) · [Quick start](#quick-start) · [Architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md)

</div>

> [!TIP]
> **WAF-protected by default.** The Docker deployment puts the official **OWASP ModSecurity Core Rule Set 4.25 LTS** in blocking mode in front of every published Intent Gate API route. The backend has no host port, while SQL injection probes, unsupported methods, malformed JSON, and oversized payloads are rejected at the edge. [Explore the WAF design and tuning guide →](docs/WAF.md)

> [!IMPORTANT]
> User Intent AI Security is an early proof of concept, not a standalone security boundary. Reliable enforcement requires integration at a command broker, shell host, agent tool API, container runtime, or privileged-operation choke point that cannot be bypassed.

## Why this project exists

Traditional endpoint controls ask whether a command is known to be malicious. That is necessary, but incomplete. A legitimate administrative command can still be dangerous when it is unexpected, mistyped, overly broad, generated without adequate review, executed under elevated privileges, or inconsistent with the task the user was performing.

User Intent AI Security adds a pre-execution decision layer. It combines command semantics with live context and returns one of three outcomes:

| Decision | Meaning | Default behavior |
|---|---|---|
| `ALLOW` | Low-risk and consistent with available context | Execute silently |
| `REVIEW` | Ambiguous, elevated, or externally consequential | Require confirmation |
| `BLOCK` | High-confidence destructive or suspicious behavior | Do not execute |

The ordinary-command hot path is local and deterministic. External APIs, SIEM queries, provenance scans, and manager notifications run asynchronously and contribute cached signals without delaying execution.

## Why this project matters

Modern command execution is no longer limited to a person carefully typing into a terminal. Commands are proposed and launched by AI coding assistants, autonomous agents, deployment systems, remote-management tools, scripts, and privileged operators working under time pressure. These systems can produce syntactically valid commands that are still wrong for the task, wrong for the target, or dangerous in the current security context.

Most controls answer one of four questions: _is the file malicious, is the identity authorized, is the command on a denylist, or did something suspicious already happen?_ User Intent AI Security explores a complementary question **before process creation**:

> **Given what this user or agent appears to be trying to accomplish, should this exact command be allowed to run here, now, with this privilege and blast radius?**

That distinction is important because many damaging actions use legitimate, signed, administrator-approved tools. `rm`, PowerShell, `terraform`, `kubectl`, cloud CLIs, database clients, and Git are indispensable—and can also erase data, disable controls, expose secrets, or change production in seconds. Intent-aware enforcement creates a place to combine the command, the task, recent behavior, privilege, project health, and live security posture into one explainable decision.

This project is intended to help teams investigate a missing security layer between **authorization** and **execution**. It does not replace EDR, SIEM, PAM, WAF, or change management; it gives those systems a chance to influence a decision before an irreversible action starts. Read the full [Project Vision](docs/PROJECT_VISION.md).

## What the project can do

| Capability | What it evaluates | Why it is useful |
|---|---|---|
| Intent-aware command gating | Command text, optional stated purpose, recent commands, and local context | Finds risky actions that do not fit the declared task |
| Three-way policy decision | `ALLOW`, `REVIEW`, or `BLOCK` with a 0–100 risk score | Supports silent low-risk work, human confirmation, and hard stops |
| Blast-radius analysis | Recursive deletion, broad targets, infrastructure destruction, cloud deletion, and other irreversible patterns | Separates a routine change from an operation with widespread impact |
| Privilege amplification | Linux root and Windows elevated administrator context | Applies greater scrutiny when the same command can do more damage |
| Behavioral anomaly detection | Per-user command-family frequency from prior gated activity | Highlights unusual administration without treating novelty alone as guilt |
| Sequence awareness | Recent sensitive actions, such as secret access followed by network transfer | Detects risk that becomes visible only across multiple commands |
| Project and release context | Git state, tests, code-health indicators, and cached provenance scan | Adds friction before publishing or deploying suspicious or unfinished code |
| Security posture correlation | Cached AV, EDR, SIEM, device, user, and project-scoped signals | Tightens command policy during an active endpoint or identity incident |
| Cross-platform destructive catalog | Windows, Linux, macOS, containers, databases, Kubernetes, cloud, Git, and recovery controls | Provides a transparent starting policy that teams can inspect and extend |
| Explainable evidence | Named signals, score contributions, command fingerprint, and latency | Lets operators understand why a decision occurred and tune policy responsibly |
| Privacy-conscious escalation | Secret redaction, local queueing, thresholds, and asynchronous webhook delivery | Enables human oversight without placing notification latency in the command path |
| Operational visibility | Prometheus metrics and a provisioned Grafana dashboard | Exposes decision volume, latency, posture, sources, and report backlog |
| Operator console | Browser-based command assessment, review queue, audit trail, and versioned decision thresholds | Makes the complete decision workflow demonstrable without executing commands from a browser |
| Pluggable model advisor | OpenAI Responses API, OpenAI-compatible endpoints, or a generic model gateway webhook | Adds an independent structured intent recommendation without making a model the enforcement authority |
| Protected integration API | OWASP CRS WAF, backend network isolation, bearer-token ingestion, and bounded requests | Reduces attack surface for the security signals that influence policy |
| Repeatable deployment | Docker Compose, Terraform, and Ansible | Makes the POC reproducible for labs, demos, and controlled evaluations |

## Where it can be used

The wrapper is the demonstration surface; the policy model can sit at any trusted point that owns process creation or privileged actions.

| Environment | Example use |
|---|---|
| AI coding agents | Evaluate every shell/tool call against the user's requested task before execution |
| Developer workstations | Review destructive commands, force pushes, package publication, and risky download-to-shell pipelines |
| Privileged access workstations | Increase scrutiny for root or administrator actions and unusual operational sequences |
| CI/CD systems | Gate deploy, publish, infrastructure-apply, and rollback commands using pipeline and security context |
| Server administration | Wrap SSH command brokers, remote-management agents, or endpoint services that create processes |
| Kubernetes and cloud operations | Add intent, scope, environment, and incident posture to destructive control-plane operations |
| Database operations | Require review or approval for destructive SQL and unusually broad maintenance actions |
| Security automation | Prevent a compromised automation identity from using legitimate tools outside its expected workflow |
| Training and purple-team labs | Demonstrate how benign tools become dangerous when purpose, sequence, privilege, and posture change |

Detailed walkthroughs—including accidental deletion, compromised admin sessions, AI-agent drift, deployment protection, and incident-aware policy—are in [Use Cases and Scenarios](docs/USE_CASES.md).

## What a decision looks like

The same executable can receive a different outcome as context changes:

| Situation | Likely result | Contributing context |
|---|---|---|
| Developer runs `git status` | `ALLOW` | Common read-only action |
| Developer force-pushes reviewed history | `REVIEW` | External side effect and history rewrite |
| Administrator deletes recovery snapshots | `BLOCK` | Destructive recovery action plus elevated privilege |
| Agent publishes from a dirty, untested project | `REVIEW` or `BLOCK` | Publish action, Git state, missing tests, and provenance risk |
| User transfers data after accessing secrets | `BLOCK` | Sequence risk and possible exfiltration |
| Routine admin command during a critical EDR alert | Stricter than normal | Privilege combined with correlated endpoint posture |

Every result includes named reasons and score contributions. The intent is not to make an opaque model the final authority; it is to create an auditable policy decision that can include deterministic rules, cached analytical signals, and human review.

## Highlights

- **Sub-millisecond policy evaluation** — approximately 0.53 ms for context collection and scoring in the development benchmark.
- **Intent-aware decisions** — evaluates declared purpose, recent activity, Git state, command behavior, and projected blast radius.
- **Privilege-sensitive policy** — detects Linux root, Linux administrative groups, and elevated Windows administrator sessions.
- **Cross-platform destructive-action catalog** — covers filesystem, storage, identity, networking, services, databases, containers, cloud resources, recovery controls, and audit-log changes.
- **Behavioral anomaly detection** — learns a local per-user baseline and identifies unusual command families.
- **AV, EDR, and SIEM context** — accepts normalized signals from common security platforms and correlates them by confidence and scope.
- **AI-assisted code risk signals** — performs a bounded, cached code-health/provenance scan without claiming unreliable authorship detection.
- **Privacy-conscious escalation** — queues redacted risk reports for an approved manager or security webhook.
- **Operational visibility** — ships with Prometheus metrics and a provisioned Grafana dashboard.
- **Protected API edge** — routes every published API request through OWASP ModSecurity CRS while keeping the backend on an internal-only network.
- **Standard-library core** — the gate has no mandatory runtime dependencies outside Python 3.11+.

## How it works

```mermaid
flowchart LR
    U["User or agent"] --> G["Intent Gate"]
    G --> C["Bounded local context"]
    C --> P["Policy engine"]
    AV["AV / EDR / SIEM"] --> N["Normalized signal cache"]
    S["Provenance scanner"] --> N
    X["Security webhooks"] --> W["OWASP CRS WAF"]
    W --> API["Signal API"]
    API --> N
    N --> P
    P -->|"Low risk"| A["ALLOW"]
    P -->|"Ambiguous"| R["REVIEW"]
    P -->|"High risk"| B["BLOCK"]
    P --> Q["Audit + redacted report queue"]
    Q --> M["Manager / security webhook"]
    Q --> O["Prometheus + Grafana"]
```

The decision engine considers:

1. The command and declared purpose.
2. Destructive capabilities and target scope.
3. Current user privilege and repository state.
4. Recent commands and the user's learned baseline.
5. Cached project provenance and code-health indicators.
6. Non-expired AV, EDR, and SIEM posture signals scoped to the device, user, or project.

See [Architecture](docs/ARCHITECTURE.md) and [Threat Model](docs/THREAT_MODEL.md) for the deeper design.

## Run the full POC demo

Docker Desktop is the fastest way to launch the complete showcase: the operator console, AI Advisor, zero-trust and micro-segmentation controls, WAF-protected API, Prometheus, and Grafana.

```powershell
Copy-Item .env.integrations.example .env.integrations
docker compose --env-file .env.integrations -f docker-compose.observability.yml up -d --build
.\scripts\Seed-DemoData.ps1
```

Open the [operator console](http://127.0.0.1:8787/) and select **AI Advisor**, **Trust Controls**, or **Audit Trail**. Grafana is available at [http://127.0.0.1:3000/](http://127.0.0.1:3000/).

The default advisor is an offline, presentation-ready simulation and is always labeled **Demo Simulation** in the interface. It produces structured `ALLOW`, `REVIEW`, and `BLOCK` recommendations without sending data to an external service. To use a real model, configure the ignored `.env.integrations` file as described in [Model Advisory Providers](docs/MODEL_ADVISORS.md).

## Quick start

### Windows PowerShell

```powershell
git clone https://github.com/BB-AI-Arena/User-Intent-AI-Security.git
cd User-Intent-AI-Security

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
. .\scripts\Enable-IntentGate.ps1

uig -- git status
uig --purpose "publish reviewed changes" --explain --dry-run -- git push
```

### Linux or macOS

```bash
git clone https://github.com/BB-AI-Arena/User-Intent-AI-Security.git
cd User-Intent-AI-Security

python3 -m venv .venv
.venv/bin/python -m pip install -e .

UIG_STATE_DIR="$PWD/.intentgate-state" .venv/bin/uig -- git status
```

Allowed commands stay quiet by default. Use `--explain` or `--json` to inspect a decision, and `--dry-run` to assess without executing.

```text
intentgate: BLOCK risk=100
   +90 destructive-action: Matched destructive catalog action(s): shadow-copy-delete.
   +25 admin-risk-amplifier: A risky command is being executed from an elevated Windows administrator session.
   +10 missing-purpose: No purpose was supplied for a risky operation.
```

### CLI reference

| Command | Purpose |
|---|---|
| `uig -- <command>` | Assess and execute a command |
| `uig --dry-run --explain -- <command>` | Assess without executing |
| `uig --purpose "..." -- <command>` | Supply the user's stated intent |
| `uig --shell -- <pipeline>` | Explicitly permit shell operators such as pipes |
| `uig-scan .` | Refresh cached project provenance signals |
| `uig-service` | Start signal-ingestion and metrics endpoints |
| `uig-collector config/integrations.json` | Poll configured security sources |
| `uig-notifier` | Deliver queued manager risk reports |

Exit codes are `0` for success, `2` for a non-allow dry run, `125` for review not approved, `126` for a blocked command, and `127` when the executable is missing.

## Risk signals

The current engine detects and correlates:

- Recursive or forced deletion and broad filesystem targets
- Filesystem formatting, raw-disk writes, partition and boot changes
- Service shutdown, firewall modification, and network resets
- User, group, ownership, ACL, and permission changes
- Scheduled persistence and security-control disabling
- Destructive SQL, container pruning, cluster deletion, and infrastructure destruction
- Cloud deletion and Git history rewrites
- Windows registry, event-log, and shadow-copy removal
- Download-to-execution pipelines, obfuscation, secret access, and potential exfiltration
- Publishing or deployment from dirty or apparently untested repositories
- Privileged execution, unusual command sequences, and external security posture

The catalog lives in [`src/intentgate/catalog.py`](src/intentgate/catalog.py) and is designed to grow into shell-specific AST policies.

## Security integrations

All integrations normalize into a small common signal:

```json
{
  "source": "microsoft-defender-xdr",
  "event_id": "alert-123",
  "score": 90,
  "confidence": 0.95,
  "ttl_seconds": 300,
  "detail": "Credential theft behavior detected",
  "scope": {"device": "EXAMPLE-HOST", "user": "example-user"}
}
```

| Integration | Method | Template status |
|---|---|---|
| Microsoft Defender Antivirus | Local PowerShell collector | Included |
| Microsoft Defender XDR | Authenticated REST polling | Included |
| Microsoft Sentinel | Authenticated REST polling | Included |
| CrowdStrike Falcon | Normalizer endpoint | Included |
| SentinelOne | Authenticated REST polling | Included |
| Splunk Enterprise Security | Export/search polling | Included |
| Elastic Security | Detection alert search | Included |
| Any security product | `POST /v1/signals` webhook | Supported |

Signals are deduplicated, confidence-weighted, scoped, and expired using TTLs. Vendor network calls never occur in the execution path. See [Integration Guide](docs/INTEGRATIONS.md).

## Grafana dashboard

Copy the example configuration and launch the observability stack:

```powershell
Copy-Item config\integrations.example.json config\integrations.json
Copy-Item .env.integrations.example .env.integrations
docker compose --env-file .env.integrations -f docker-compose.observability.yml up -d --build
```

| Service | Default URL |
|---|---|
| Grafana | `http://localhost:3000` |
| Prometheus | `http://localhost:9090` |
| WAF-protected Intent Gate API | `http://localhost:8787` |

The dashboard tracks aggregate security posture, active external signals, decision counts, policy latency, source-level risk, audited commands, and pending manager reports.

## Operator console

The Intent Gate service includes a local operator console for exercising the policy workflow. Start the service and open `http://127.0.0.1:8787/`:

```powershell
$env:UIG_INGEST_TOKEN = "local-dev-change-me"
uig-service
```

Use **Set API token** in the console to enter the configured bearer token. The token is retained only in the current browser tab. The console provides:

- Command and purpose assessment with complete score contributions
- `ALLOW`, `REVIEW`, and `BLOCK` results with policy version and latency
- A human review queue with approve and deny decisions
- An expandable audit surface with user, endpoint, risk score, and scored decision evidence
- Versioned, locally persisted review and block thresholds
- Versioned zero-trust step-up controls and a micro-segmentation flow designer
- An inspectable destructive-action rule catalog

The console is intentionally **assessment-only**. Approving a review records human authorization but never launches the command from the browser. A trusted command broker remains the required production execution boundary.

HTTP assessments use a standard `console-operator` execution context by default rather than inheriting the container service account's root identity. A trusted broker can submit an explicit `execution_context` containing the originating user and privilege level; production enforcement must authenticate that context rather than accepting it directly from an untrusted client.

### Trust controls

The **Trust Controls** console section persists an authenticated local control-plane profile. Zero-trust settings can require declared intent and posture, retain continuous behavior monitoring, and step an otherwise allowed action up to human review at a configured risk threshold. Micro-segmentation settings expose the five Compose network zones and an explicit allow-list of service flows. Network-policy edits are marked `redeploy-required`; saving the design does not silently rewrite or restart Docker networking.

### AI model advisory

The local Docker showcase starts with a clearly labeled, offline Demo Simulation advisor so model-health and structured verdict UI can be demonstrated without a credential. The simulation never contacts an external model and is not an independent security judgment. Configure OpenAI in the ignored `.env.integrations` file to replace it:

```env
UIG_MODEL_PROVIDER=openai
UIG_MODEL_NAME=gpt-5.6-luna
UIG_MODEL_API_KEY=replace-with-an-api-key
```

Recreate the service with `docker compose --env-file .env.integrations -f docker-compose.observability.yml up -d --build intentgate waf`. Local OpenAI-compatible servers and generic frontier-model gateways use the same normalized result contract. See [Model Advisory Providers](docs/MODEL_ADVISORS.md).

### Load showcase data

With the Docker stack running, populate both the operator console and Grafana with a repeatable demo scenario:

```powershell
.\scripts\Seed-DemoData.ps1
```

The seed includes routine development activity, publish and deployment reviews, blocked recovery/security-control operations, manager reports, and correlated Microsoft Defender XDR, CrowdStrike Falcon, and Microsoft Sentinel signals. Every command is assessed only; the seed never executes the submitted command text.

## Web application firewall

Docker deployments publish the official OWASP ModSecurity Core Rule Set Nginx proxy instead of the application container. The backend has no host port and lives on an internal-only network. Blocking is enabled by default at paranoia level 1, with additional level 2 detection telemetry, strict HTTP methods and content types, a 1 MiB body limit, disabled routine access logging, and bounded audit logs that exclude request headers and bodies.

```bash
curl http://127.0.0.1:8787/healthz
docker compose -f docker-compose.observability.yml logs waf
```

Configuration is available through the ignored environment file and the Ansible role. Review [WAF Operations](docs/WAF.md) before changing thresholds, adding rule exclusions, or publishing the listener beyond loopback.

> [!WARNING]
> Development credentials are intentionally simple. Change all passwords and tokens before exposing any service beyond localhost.

## Manager escalation

High-risk, blocked, or strongly anomalous commands create a local risk report. Likely passwords, tokens, API keys, bearer values, URL credentials, and common secret assignments are redacted before delivery.

```powershell
$env:UIG_MANAGER_ID = "security-operations"
$env:UIG_MANAGER_REPORT_THRESHOLD = "70"
$env:UIG_MANAGER_WEBHOOK_URL = "https://webhook.example.invalid/security"
$env:UIG_MANAGER_WEBHOOK_STYLE = "generic" # generic, slack, or teams
uig-notifier
```

Reporting is disabled until explicitly configured, and command execution never waits for delivery. Organizations should establish employee notice, retention, access control, and appeal procedures before deployment.

## Infrastructure as code

The repository includes two supported automation paths. Both reuse the canonical Compose definition instead of maintaining divergent copies of the application stack.

### Terraform

The [`deploy/terraform`](deploy/terraform) root module uses the `kreuzwerker/docker` provider's native `docker_compose` resource. It supports local engines, named Docker contexts, remote daemon URIs, optional environment files, Compose profiles, health waiting, and clean Terraform-managed teardown.

```bash
cd deploy/terraform
terraform init
terraform plan
terraform apply
```

### Ansible

The [`deploy/ansible`](deploy/ansible) role can bootstrap Docker Engine and Compose v2 on a Debian-family server, check out an approved version, render a protected environment file from Ansible Vault variables, deploy the stack, and verify the Intent Gate health endpoint.

```bash
cd deploy/ansible
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i inventories/production.ini deploy.yml --ask-vault-pass
```

Terraform state, local variable files, production inventories, host variables, Vault material, and rendered secrets are excluded from Git. See the individual Terraform and Ansible guides for remote-host and lifecycle details.

## Development

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q src tests
docker compose -f docker-compose.observability.yml config --quiet
```

The current suite covers policy outcomes, destructive patterns, privilege amplification, behavioral baselines, external signal correlation, reporting redaction, notifier delivery, service ingestion, and Prometheus metrics.

## Project status

Version **0.4.0** is a research-quality proof of concept. Important production work remains:

- Enforce at a non-bypassable execution boundary.
- Replace command regexes with PowerShell, POSIX shell, and command AST parsers.
- Resolve concrete filesystem, cloud, database, and infrastructure targets before execution.
- Add signed policy bundles, policy versioning, exception workflows, and tamper protection.
- Add explicit feed-health policy with fail-open, fail-closed, and review-only modes.
- Evaluate anomaly quality against representative benign and adversarial datasets.
- Add durable encrypted storage and enterprise identity for reports and policy administration.

### What this POC proves today

- A useful decision can be produced without placing network or model calls in the execution hot path.
- Legitimate tools can be evaluated by purpose, sequence, privilege, scope, project state, and external posture—not only by binary reputation.
- AV, EDR, SIEM, WAF, audit, reporting, and user-context signals can be normalized around a single pre-execution decision.
- The decision can remain explainable enough for testing, policy tuning, and human review.

### Path toward production

The next stage is a protected, persistent command broker with shell-specific parsing, resolved resource targets, signed policies, enterprise identity, approval workflows, tamper-resistant storage, and measured false-positive/false-negative performance. See the [Project Vision](docs/PROJECT_VISION.md#roadmap-from-poc-to-production) for the proposed phases and success criteria.

## Responsible use

This project observes commands and can generate workplace security reports. Deploy it transparently, collect only what is necessary, protect the resulting data, and provide meaningful human review. Do not treat anomaly scores or AI-related signals as proof of malicious intent.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), review the [Security Policy](SECURITY.md), and use the provided issue templates.

## License

Licensed under the [MIT License](LICENSE).
