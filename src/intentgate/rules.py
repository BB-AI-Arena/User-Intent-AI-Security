from __future__ import annotations

import re
from pathlib import Path

from .catalog import match_destructive_actions
from .models import CommandContext, Signal


DESTRUCTIVE = re.compile(
    r"(?:^|\s)(?:rm\s+-[^\n]*r|rmdir\s+/s|del\s+/[sq]|remove-item\b[^\n]*(?:-recurse|-force)|"
    r"format(?:\.com)?\b|mkfs\b|diskpart\b|drop\s+(?:database|table)\b|truncate\s+table\b)",
    re.IGNORECASE,
)
PRIVILEGE = re.compile(r"(?:^|\s)(?:sudo|runas|doas|set-executionpolicy|takeown|icacls)\b", re.IGNORECASE)
NETWORK_EXEC = re.compile(
    r"(?:curl|wget|irm|invoke-restmethod|iwr|invoke-webrequest)[^\n|;]*(?:\||;|&&)\s*(?:sh|bash|pwsh|powershell|python|node)",
    re.IGNORECASE,
)
SECRET_ACCESS = re.compile(r"(?:\.env\b|id_rsa|credentials|secrets?\.|token\b|keychain)", re.IGNORECASE)
EXFIL = re.compile(r"(?:curl|wget|scp|rsync|invoke-restmethod|invoke-webrequest)\b", re.IGNORECASE)
OBFUSCATION = re.compile(r"(?:frombase64string|-enc(?:odedcommand)?\b|base64\s+-d|eval\s*\(|iex\b)", re.IGNORECASE)
PUBLISH = re.compile(r"(?:git\s+push|npm\s+publish|twine\s+upload|docker\s+push|kubectl\s+apply|terraform\s+apply)", re.IGNORECASE)
READ_ONLY = re.compile(
    r"^(?:git\s+(?:status|diff|log|show|branch)|(?:ls|dir|pwd|whoami|where|which|type|get-childitem|get-content|rg)\b|"
    r"(?:python|node|git|docker|npm|pip)\s+--version)",
    re.IGNORECASE,
)


def _targets_broad_scope(command: str, cwd: str) -> bool:
    normalized = command.replace("\\", "/").lower()
    broad = (" / " in f" {normalized} ", " c:/" in normalized, " $home" in normalized, " ~" in normalized)
    if any(broad):
        return True
    # Parent traversal plus destructive operation is a blast-radius hint.
    return "../" in normalized or "..\\" in command.lower()


def evaluate_rules(ctx: CommandContext) -> list[Signal]:
    command = ctx.command.strip()
    signals: list[Signal] = []
    if not command:
        return [Signal("empty-command", 100, "No executable command was supplied.")]
    if ctx.is_root:
        signals.append(Signal("privilege-context", 0, "Current process is running as Linux root."))
    elif ctx.is_admin:
        signals.append(Signal("privilege-context", 0, f"Current user/process privilege is {ctx.privilege_level}."))
    if READ_ONLY.search(command):
        signals.append(Signal("read-only", -25, "Command matches a common read-only operation."))
    destructive_actions = match_destructive_actions(command)
    if destructive_actions:
        highest = max(item.score for item in destructive_actions)
        names = ", ".join(item.identifier for item in destructive_actions[:3])
        signals.append(Signal("destructive-action", highest, f"Matched destructive catalog action(s): {names}."))
    elif DESTRUCTIVE.search(command):
        signals.append(Signal("destructive", 55, "Command can delete or irreversibly alter data."))
    if PRIVILEGE.search(command):
        signals.append(Signal("privilege", 25, "Command requests or changes elevated privileges."))
    if NETWORK_EXEC.search(command):
        signals.append(Signal("network-to-execution", 80, "Downloaded content appears to flow directly into an interpreter."))
    if OBFUSCATION.search(command):
        signals.append(Signal("obfuscation", 45, "Command contains an encoding or dynamic-execution pattern."))
    if SECRET_ACCESS.search(command):
        signals.append(Signal("secret-access", 25, "Command references likely credentials or secrets."))
    if SECRET_ACCESS.search(command) and EXFIL.search(command):
        signals.append(Signal("possible-exfiltration", 55, "Network transfer and secret access occur together."))
    if PUBLISH.search(command):
        signals.append(Signal("external-side-effect", 30, "Command can publish or modify external infrastructure."))
    if DESTRUCTIVE.search(command) and _targets_broad_scope(command, ctx.cwd):
        signals.append(Signal("large-blast-radius", 45, "Destructive command appears to target a broad or parent scope."))
    if ctx.git_dirty and (DESTRUCTIVE.search(command) or PUBLISH.search(command)):
        signals.append(Signal("dirty-worktree", 15, "Risky operation is being run with uncommitted changes."))
    if "ai-editor-metadata" in ctx.project_signals or "generated-app-metadata" in ctx.project_signals:
        signals.append(Signal("ai-assisted-project", 5, "Project contains AI-tool metadata; provenance confidence is reduced slightly."))
    if "no-obvious-tests" in ctx.project_signals and PUBLISH.search(command):
        signals.append(Signal("untested-publish", 20, "No obvious test directory was found before a publish/deploy operation."))
    if ctx.provenance_risk >= 60 and (PUBLISH.search(command) or PRIVILEGE.search(command)):
        detail = ctx.provenance_details[0] if ctx.provenance_details else "Cached project provenance risk is high."
        signals.append(Signal("provenance-risk", 25, detail))
    if ctx.external_risk >= 90:
        sources = ", ".join(ctx.external_sources) or "external security tools"
        signals.append(Signal("critical-security-posture", 55, f"{sources} report critical correlated risk ({ctx.external_risk}/100)."))
    elif ctx.external_risk >= 70:
        sources = ", ".join(ctx.external_sources) or "external security tools"
        signals.append(Signal("high-security-posture", 30, f"{sources} report high correlated risk ({ctx.external_risk}/100)."))
    elif ctx.external_risk >= 40:
        sources = ", ".join(ctx.external_sources) or "external security tools"
        signals.append(Signal("elevated-security-posture", 15, f"{sources} report elevated correlated risk ({ctx.external_risk}/100)."))
    risky_base = sum(signal.score for signal in signals if signal.score > 0)
    if ctx.is_root and risky_base >= 30:
        signals.append(Signal("root-risk-amplifier", 30, "A risky command is being executed as Linux root."))
    elif ctx.is_admin and risky_base >= 30:
        signals.append(Signal("admin-risk-amplifier", 25, "A risky command is being executed from an elevated Windows administrator session."))
    if ctx.anomaly_score >= 20 and risky_base >= 25:
        detail = ctx.anomaly_details[0] if ctx.anomaly_details else "Command is unusual for this user's recent baseline."
        signals.append(Signal("behavioral-anomaly", min(30, ctx.anomaly_score), detail))
    if ctx.purpose:
        purpose_terms = {w for w in re.findall(r"[a-z0-9]+", ctx.purpose.lower()) if len(w) > 3}
        command_terms = set(re.findall(r"[a-z0-9]+", command.lower()))
        if purpose_terms and not (purpose_terms & command_terms) and sum(s.score for s in signals) >= 30:
            signals.append(Signal("purpose-mismatch", 20, "Declared purpose has little lexical overlap with a risky command."))
    elif sum(s.score for s in signals) >= 30:
        signals.append(Signal("missing-purpose", 10, "No purpose was supplied for a risky operation."))
    if ctx.recent_commands:
        recent = "\n".join(ctx.recent_commands[-4:])
        if SECRET_ACCESS.search(recent) and EXFIL.search(command):
            signals.append(Signal("sequence-risk", 35, "Recent secret access followed by network transfer increases exfiltration risk."))
    return signals
