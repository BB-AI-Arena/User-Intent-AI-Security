# Threat Model

## Protected outcomes

- Prevent unintended destructive or externally consequential commands.
- Increase scrutiny when elevated privilege, unusual behavior, or external security alerts coincide.
- Preserve sufficient redacted evidence for human review.
- Keep ordinary command latency low and vendor failures isolated.

## In-scope threats

- Accidental destructive commands and excessive blast radius
- Malicious or compromised user sessions
- Agent-generated commands that diverge from the stated task
- Download-and-execute pipelines and encoded execution
- Secret access followed by potential exfiltration
- Security-control weakening, log erasure, persistence, and recovery deletion
- Risky commands during an active AV, EDR, or SIEM incident

## Out of scope for the POC

- Kernel-level process prevention
- Complete shell parsing and script interpretation
- Memory-only attacks and kernel exploits
- Trustworthy attribution of whether code was AI-generated
- Protection when users bypass the wrapper
- Guaranteed correctness of third-party security feeds

## Trust boundaries

The local state directory, policy code, process-launch integration, manager webhook, and integration credentials are trusted. Production deployments must protect them against unauthorized modification.

## Known failure modes

- False positives from legitimate but rare administrative work
- False negatives from aliases, custom scripts, indirect execution, or novel syntax
- Stale or mis-scoped external signals
- Sensitive operational text surviving imperfect redaction
- Baseline poisoning by repeated malicious behavior

Mitigations include human review, signed policies, protected baselines, explicit feed-health rules, shell-specific AST parsing, target resolution, and retention controls.

