from __future__ import annotations

import argparse
import json
import subprocess
import sys

from .audit import record
from .context import collect_context
from .engine import assess
from .models import Decision


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="uig", description="Context-aware command intent gate")
    parser.add_argument("--purpose", help="Short statement of what the user is trying to accomplish")
    parser.add_argument("--explain", action="store_true", help="Print all decision signals")
    parser.add_argument("--json", action="store_true", help="Print the assessment as JSON")
    parser.add_argument("--dry-run", action="store_true", help="Assess without executing")
    parser.add_argument("--yes", action="store_true", help="Approve REVIEW decisions non-interactively")
    parser.add_argument("--shell", action="store_true", help="Execute shell operators such as pipes and redirects")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command after --")
    return parser


def _display(result, verbose: bool) -> None:
    print(f"intentgate: {result.decision.value.upper()} risk={result.risk_score} ({result.latency_ms:.3f} ms)")
    if verbose:
        for signal in result.signals:
            sign = "+" if signal.score >= 0 else ""
            print(f"  {sign}{signal.score:>3} {signal.name}: {signal.detail}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        _parser().error("supply a command after --")

    ctx = collect_context(command, args.purpose)
    result = assess(ctx)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    elif args.explain or result.decision is not Decision.ALLOW or args.dry_run:
        _display(result, args.explain)

    if args.dry_run:
        record(ctx, result, executed=False)
        return 0 if result.decision is Decision.ALLOW else 2
    if result.decision is Decision.BLOCK:
        record(ctx, result, executed=False)
        print("intentgate: blocked; revise the command or policy", file=sys.stderr)
        return 126
    if result.decision is Decision.REVIEW and not args.yes:
        if not sys.stdin.isatty():
            record(ctx, result, executed=False)
            print("intentgate: review required; rerun interactively or pass --yes", file=sys.stderr)
            return 125
        approved = input("intentgate: allow this command? [y/N] ").strip().lower() in {"y", "yes"}
        if not approved:
            record(ctx, result, executed=False)
            return 125

    try:
        if args.shell:
            completed = subprocess.run(" ".join(command), cwd=ctx.cwd, shell=True)
        else:
            completed = subprocess.run(command, cwd=ctx.cwd)
        code = completed.returncode
    except FileNotFoundError:
        record(ctx, result, executed=False)
        print(f"intentgate: executable not found: {command[0]}", file=sys.stderr)
        return 127
    record(ctx, result, executed=True, exit_code=code)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
