from __future__ import annotations

import hashlib
import time

from .models import Assessment, CommandContext, Decision
from .policy import load_policy
from .rules import evaluate_rules


def assess(ctx: CommandContext) -> Assessment:
    started = time.perf_counter_ns()
    policy = load_policy()
    signals = evaluate_rules(ctx)
    score = max(0, min(100, sum(signal.score for signal in signals)))
    if score >= policy["block_threshold"]:
        decision = Decision.BLOCK
    elif score >= policy["review_threshold"]:
        decision = Decision.REVIEW
    else:
        decision = Decision.ALLOW
    fingerprint = hashlib.blake2s(ctx.command.encode("utf-8"), digest_size=8).hexdigest()
    elapsed = (time.perf_counter_ns() - started) / 1_000_000
    return Assessment(
        decision, score, signals, elapsed, fingerprint,
        policy_name=policy["name"], policy_version=policy["version"],
    )

