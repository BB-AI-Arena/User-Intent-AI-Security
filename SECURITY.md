# Security Policy

## Project status

User Intent AI Security is a proof of concept. Do not rely on it as the sole control protecting production systems, privileged accounts, sensitive data, or safety-critical infrastructure.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could expose users or deployment details. Use GitHub's private vulnerability reporting feature for this repository when available. Include:

- A clear description of the issue and potential impact
- Affected version, platform, and configuration
- Reproduction steps or a minimal proof of concept
- Any suggested mitigation

You should receive an initial acknowledgment within seven days. Disclosure timing will be coordinated after the issue is understood and a mitigation is available.

## Security assumptions

- The command wrapper is bypassable unless integrated at a trusted execution boundary.
- Regex-based command classification cannot resolve every alias, script, encoded payload, child process, or shell grammar edge case.
- External feeds may be stale, unavailable, compromised, or incorrectly scoped.
- Behavioral anomalies and AI-related code signals are risk indicators, not proof of malicious intent.
- Audit history and manager reports may contain sensitive operational metadata even after secret redaction.

## Deployment guidance

- Bind ingestion and metrics services to trusted interfaces only.
- Replace every development credential before deployment.
- Use TLS, authenticated webhooks, least-privilege API credentials, and restricted storage permissions.
- Define retention and access policies for audit data and manager reports.
- Validate integration mappings against the deployed vendor version.
- Decide explicitly whether stale feeds fail open, fail closed, or require review.

