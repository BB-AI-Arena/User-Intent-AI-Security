from __future__ import annotations

import hashlib
import time

from .models import Assessment, CommandContext, Decision
from .rules import evaluate_rules


def assess(ctx: CommandContext) -> Assessment:
    started = time.perf_counter_ns()
    signals = evaluate_rules(ctx)
    score = max(0, min(100, sum(signal.score for signal in signals)))
    if score >= 85:
        decision = Decision.BLOCK
    elif score >= 40:
        decision = Decision.REVIEW
    else:
        decision = Decision.ALLOW
    fingerprint = hashlib.blake2s(ctx.command.encode("utf-8"), digest_size=8).hexdigest()
    elapsed = (time.perf_counter_ns() - started) / 1_000_000
    return Assessment(decision, score, signals, elapsed, fingerprint)

