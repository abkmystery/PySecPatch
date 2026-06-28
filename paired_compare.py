"""Paired base-versus-adapter comparison for PySecPatch JSONL predictions."""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any


SEED = 20260627
METRICS = {
    "classification_correct": "all",
    "json_valid": "all",
    "schema_valid": "all",
    "negative_preserved": "negative",
    "security_control_pass": "vulnerable",
    "no_dangerous_regression": "vulnerable",
    "fixed_normalized_exact": "vulnerable",
    "fixed_structural_exact": "vulnerable",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def applies(record: dict[str, Any], population: str) -> bool:
    vulnerable = bool(record["is_vulnerable"])
    return population == "all" or (population == "vulnerable" and vulnerable) or (
        population == "negative" and not vulnerable
    )


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    index = (len(ordered) - 1) * q
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def exact_mcnemar_log10(left_only: int, right_only: int) -> float:
    discordant = left_only + right_only
    if not discordant:
        return 0.0
    tail = min(left_only, right_only)
    numerator = 2 * sum(math.comb(discordant, value) for value in range(tail + 1))
    return math.log10(numerator) - discordant * math.log10(2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--final", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bootstrap-samples", type=int, default=10_000)
    args = parser.parse_args()

    base = {row["id"]: row for row in read_jsonl(args.base)}
    final = {row["id"]: row for row in read_jsonl(args.final)}
    records = {
        row["id"]: row
        for row in read_jsonl(args.dataset)
        if row.get("task") in {"detect", "repair"}
    }
    identifiers = sorted(set(base) & set(final) & set(records))
    if len(identifiers) != len(records):
        raise RuntimeError("Predictions do not exactly cover the requested dataset.")

    families: dict[str, list[str]] = defaultdict(list)
    for identifier in identifiers:
        families[records[identifier]["family"]].append(identifier)
    family_names = sorted(families)
    rng = random.Random(SEED)

    metrics: dict[str, Any] = {}
    for metric, population in METRICS.items():
        eligible = [identifier for identifier in identifiers if applies(records[identifier], population)]
        base_values = [float(bool(base[i]["scores"].get(metric))) for i in eligible]
        final_values = [float(bool(final[i]["scores"].get(metric))) for i in eligible]
        observed = mean(final_values) - mean(base_values)

        family_totals: dict[str, tuple[float, float, int]] = {}
        for family in family_names:
            family_ids = [
                identifier
                for identifier in families[family]
                if applies(records[identifier], population)
            ]
            family_totals[family] = (
                sum(float(bool(base[i]["scores"].get(metric))) for i in family_ids),
                sum(float(bool(final[i]["scores"].get(metric))) for i in family_ids),
                len(family_ids),
            )
        bootstrap: list[float] = []
        for _ in range(args.bootstrap_samples):
            sampled_families = [rng.choice(family_names) for _ in family_names]
            base_sum = sum(family_totals[family][0] for family in sampled_families)
            final_sum = sum(family_totals[family][1] for family in sampled_families)
            count = sum(family_totals[family][2] for family in sampled_families)
            if count:
                bootstrap.append(final_sum / count - base_sum / count)
        metrics[metric] = {
            "population": population,
            "records": len(eligible),
            "base": mean(base_values),
            "final": mean(final_values),
            "difference_final_minus_base": observed,
            "cluster_bootstrap_95ci": [percentile(bootstrap, 0.025), percentile(bootstrap, 0.975)],
        }

    base_only = sum(
        bool(base[i]["scores"]["classification_correct"])
        and not bool(final[i]["scores"]["classification_correct"])
        for i in identifiers
    )
    final_only = sum(
        bool(final[i]["scores"]["classification_correct"])
        and not bool(base[i]["scores"]["classification_correct"])
        for i in identifiers
    )
    result = {
        "schema_version": 1,
        "seed": SEED,
        "shared_records": len(identifiers),
        "family_clusters": len(family_names),
        "bootstrap_samples": args.bootstrap_samples,
        "mcnemar": {
            "base_only_correct": base_only,
            "final_only_correct": final_only,
            "discordant": base_only + final_only,
            "exact_two_sided_log10_p": exact_mcnemar_log10(base_only, final_only),
        },
        "metrics": metrics,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
