# Changelog

All notable changes to this project will be documented here.

## [0.4.0] - 2026-08-12

### Added

- OWASP ModSecurity Core Rule Set WAF in front of every published Intent Gate API route
- Internal-only application network that prevents direct host access to the API backend
- Tunable blocking and detection paranoia levels, anomaly thresholds, bind address, and port
- Bounded, metadata-only WAF audit logging and a deployment smoke test
- WAF configuration support in the Ansible deployment role

## [0.3.0] - 2026-08-12

### Added

- Low-latency `ALLOW`, `REVIEW`, and `BLOCK` command policy engine
- Windows and Linux privilege detection
- Cross-platform destructive-action catalog
- Per-user behavioral command baseline and anomaly scoring
- Cached project provenance and code-health scanning
- Normalized AV, EDR, and SIEM signal ingestion
- Microsoft Defender local collector and enterprise integration templates
- Prometheus metrics and provisioned Grafana dashboard
- Redacted asynchronous manager/security risk reports
- Generic, Slack, and Microsoft Teams webhook delivery
- Automated tests and repository governance documentation
- Terraform Docker Compose deployment module
- Ansible Linux host bootstrap and secure deployment role
