from __future__ import annotations

import json
import os
import getpass
import socket
import subprocess
from pathlib import Path

from .models import CommandContext
from .provenance import read_cached_scan
from .integrations import read_posture
from .behavior import assess_anomaly
from .privilege import detect_privilege


STATE_DIR = Path(os.environ.get("UIG_STATE_DIR", Path.home() / ".intentgate"))
HISTORY_FILE = STATE_DIR / "history.jsonl"


def _git(cwd: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=0.08
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def _find_git_root(cwd: Path) -> Path | None:
    for candidate in (cwd, *cwd.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def recent_commands(limit: int = 8) -> tuple[str, ...]:
    try:
        lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()[-limit:]
    except OSError:
        return ()
    items: list[str] = []
    for line in lines:
        try:
            items.append(str(json.loads(line)["command"]))
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return tuple(items)


def project_provenance_signals(cwd: Path) -> tuple[str, ...]:
    """Cheap signals only. A future background analyzer can populate richer facts."""
    markers = {
        "package.json": "node-project",
        "pyproject.toml": "python-project",
        "requirements.txt": "python-project",
        "Cargo.toml": "rust-project",
        "go.mod": "go-project",
        ".openai": "generated-app-metadata",
        ".cursor": "ai-editor-metadata",
        ".windsurf": "ai-editor-metadata",
    }
    signals = {label for name, label in markers.items() if (cwd / name).exists()}
    has_tests = any((cwd / name).exists() for name in ("tests", "test", "__tests__"))
    if not has_tests and signals & {"node-project", "python-project", "rust-project", "go-project"}:
        signals.add("no-obvious-tests")
    return tuple(sorted(signals))


def collect_context(argv: list[str], purpose: str | None = None, cwd: str | None = None) -> CommandContext:
    path = Path(cwd or os.getcwd()).resolve()
    root_path = _find_git_root(path)
    git_root = str(root_path) if root_path else None
    branch = _git(path, "branch", "--show-current") if root_path else None
    dirty = bool(_git(path, "status", "--porcelain")) if root_path else False
    project_root = root_path or path
    provenance = read_cached_scan(project_root)
    user_name = getpass.getuser()
    posture = read_posture(
        device=socket.gethostname(),
        user=user_name,
        project=str(project_root),
    )
    privilege = detect_privilege()
    anomaly = assess_anomaly(" ".join(argv), user_name=user_name)
    return CommandContext(
        cwd=str(path),
        command=" ".join(argv),
        argv=tuple(argv),
        purpose=purpose,
        recent_commands=recent_commands(),
        git_root=git_root,
        git_branch=branch,
        git_dirty=dirty,
        project_signals=project_provenance_signals(project_root),
        provenance_risk=int(provenance.get("risk_score", 0)),
        provenance_details=tuple(str(item) for item in provenance.get("details", ())),
        external_risk=int(posture.get("risk_score", 0)),
        external_sources=tuple(str(item) for item in posture.get("sources", ())),
        external_details=tuple(str(item) for item in posture.get("details", ())),
        user_name=user_name,
        is_root=privilege.is_root,
        is_admin=privilege.is_admin,
        privilege_level=privilege.level,
        anomaly_score=int(anomaly.get("score", 0)),
        anomaly_details=tuple(str(item) for item in anomaly.get("details", ())),
    )
