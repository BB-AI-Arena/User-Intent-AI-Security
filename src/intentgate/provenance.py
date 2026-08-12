from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any


SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".cs", ".ps1", ".sh"}
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage", "vendor"}
AI_MARKERS = re.compile(r"(?:generated\s+by|chatgpt|claude|copilot|cursor\s+ai|as\s+an\s+ai)", re.IGNORECASE)
PLACEHOLDERS = re.compile(r"\b(?:TODO|FIXME|HACK|placeholder|not\s+implemented)\b", re.IGNORECASE)
SWALLOWED_ERRORS = re.compile(r"except\s+(?:Exception|BaseException)?\s*:\s*(?:#.*\n\s*)?pass\b", re.IGNORECASE)


def _state_dir() -> Path:
    return Path(os.environ.get("UIG_STATE_DIR", Path.home() / ".intentgate"))


def _cache_path(root: Path) -> Path:
    key = hashlib.blake2s(str(root.resolve()).lower().encode("utf-8"), digest_size=10).hexdigest()
    return _state_dir() / "provenance" / f"{key}.json"


def _source_files(root: Path, limit: int = 250):
    count = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in IGNORED_DIRS and not name.startswith(".")]
        for name in files:
            path = Path(current) / name
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            yield path
            count += 1
            if count >= limit:
                return


def scan_project(root: Path, limit: int = 250) -> dict[str, Any]:
    root = root.resolve()
    files = list(_source_files(root, limit))
    test_files = [path for path in files if "test" in path.name.lower() or "tests" in path.parts]
    ai_markers = placeholders = swallowed = large_files = unreadable = 0
    lines = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:300_000]
        except OSError:
            unreadable += 1
            continue
        line_count = text.count("\n") + 1
        lines += line_count
        large_files += int(line_count > 1200)
        ai_markers += len(AI_MARKERS.findall(text))
        placeholders += len(PLACEHOLDERS.findall(text))
        swallowed += len(SWALLOWED_ERRORS.findall(text))

    score = 0
    details: list[str] = []
    if files and not test_files:
        score += 25
        details.append("No test source files were found in the bounded scan.")
    if ai_markers:
        score += min(15, ai_markers * 3)
        details.append(f"Found {ai_markers} explicit AI-generation/provenance marker(s).")
    if placeholders >= 8:
        score += min(20, placeholders)
        details.append(f"Found {placeholders} placeholder or unfinished-code marker(s).")
    if swallowed:
        score += min(20, swallowed * 5)
        details.append(f"Found {swallowed} broad exception handler(s) that silently discard errors.")
    if large_files:
        score += min(15, large_files * 5)
        details.append(f"Found {large_files} source file(s) over 1,200 lines.")
    if not files:
        details.append("No supported source files were found; provenance confidence is unknown.")

    result = {
        "schema_version": 1,
        "root": str(root),
        "scanned_at": time.time(),
        "risk_score": min(100, score),
        "details": details,
        "metrics": {
            "source_files": len(files),
            "test_files": len(test_files),
            "lines_sampled": lines,
            "ai_markers": ai_markers,
            "placeholders": placeholders,
            "swallowed_errors": swallowed,
            "large_files": large_files,
            "unreadable_files": unreadable,
            "file_limit": limit,
        },
    }
    cache = _cache_path(root)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def read_cached_scan(root: Path, max_age_seconds: int = 86_400) -> dict[str, Any]:
    try:
        result = json.loads(_cache_path(root).read_text(encoding="utf-8"))
        if time.time() - float(result["scanned_at"]) > max_age_seconds:
            return {}
        return result
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cache bounded project provenance signals for Intent Gate")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--limit", type=int, default=250)
    args = parser.parse_args(argv)
    result = scan_project(Path(args.path), max(1, min(args.limit, 2_000)))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
