"""Evaluate PySecPatch v2 repository-patch JSON and unified-diff behavior."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import random
import statistics
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent import SecurityVisitor
from data import AGENT_FIELDS, SPECS, _apply_unified_diff
from models import TransformersRepairModel


PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
RESULTS_DIR = PROJECT_DIR / "results"
SEED = 20260627


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_tree(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        digest.update(item.relative_to(path).as_posix().encode())
        digest.update(_sha256_file(item).encode())
    return digest.hexdigest()


def _split_path(split: str) -> Path:
    return DATA_DIR / f"v2_{split}.jsonl"


def _read_records(split: str, limit: int) -> list[dict[str, Any]]:
    path = _split_path(split)
    records = [
        row
        for row in (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines())
        if row.get("task") == "repo_patch"
    ]
    if not records:
        raise RuntimeError(f"No repository-patch records found in {path}")
    if limit > 0:
        groups: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            groups.setdefault(record["cwe"], []).append(record)
        rng = random.Random(SEED)
        for values in groups.values():
            rng.shuffle(values)
        selected: list[dict[str, Any]] = []
        while len(selected) < min(limit, len(records)):
            changed = False
            for cwe in sorted(groups):
                if groups[cwe] and len(selected) < limit:
                    selected.append(groups[cwe].pop())
                    changed = True
            if not changed:
                break
        records = selected
    return records


def _spec(record: dict[str, Any]) -> Any | None:
    return next((item for item in SPECS if f"-{item.slug}-" in record["family"]), None)


def _finding_counts(code: str) -> Counter[str]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return Counter()
    visitor = SecurityVisitor("app.py", code)
    visitor.visit(tree)
    return Counter(item["check"] for item in visitor.findings)


def _score(record: dict[str, Any], inference: dict[str, Any]) -> dict[str, Any]:
    output = inference.get("output")
    schema_valid = (
        isinstance(output, dict)
        and set(output) == set(AGENT_FIELDS)
        and all(isinstance(output[field], str) for field in AGENT_FIELDS)
    )
    scores: dict[str, Any] = {
        "json_valid": not inference.get("invalid_json", True),
        "schema_valid": schema_valid,
        "finding_id_exact": False,
        "summary_nonempty": False,
        "relevant_file_only": False,
        "patch_applies": False,
        "patched_code_parseable": False,
        "patched_code_exact": False,
        "security_control_pass": False,
        "no_dangerous_regression": False,
    }
    if not schema_valid:
        return scores
    assert isinstance(output, dict)
    scores["finding_id_exact"] = output["finding_id"] == record["target"]["finding_id"]
    scores["summary_nonempty"] = bool(output["summary"].strip())
    patch = output["patch"]
    headers = [line for line in patch.splitlines() if line.startswith(("--- ", "+++ "))]
    scores["relevant_file_only"] = headers == ["--- a/app.py", "+++ b/app.py"]
    if not scores["relevant_file_only"]:
        return scores
    try:
        patched = _apply_unified_diff(record["vulnerable_code"], patch)
    except (ValueError, IndexError):
        return scores
    scores["patch_applies"] = True
    try:
        ast.parse(patched)
        scores["patched_code_parseable"] = True
    except SyntaxError:
        return scores
    scores["patched_code_exact"] = patched == record["fixed_code"]
    profile = _spec(record)
    control = profile is not None
    if control and profile.forbidden_test_text:
        control = profile.forbidden_test_text not in patched
    if control and profile.required_test_text:
        control = profile.required_test_text in patched
    scores["security_control_pass"] = bool(control)
    before = _finding_counts(record["vulnerable_code"])
    after = _finding_counts(patched)
    scores["no_dangerous_regression"] = all(after[key] <= before[key] for key in after)
    return scores


def _mean(rows: list[dict[str, Any]], key: str) -> float:
    return sum(float(bool(row["scores"][key])) for row in rows) / len(rows) if rows else 0.0


def _bootstrap(rows: list[dict[str, Any]], key: str, samples: int) -> dict[str, float]:
    values = [float(bool(row["scores"][key])) for row in rows]
    estimate = sum(values) / len(values)
    rng = random.Random(SEED)
    draws = sorted(sum(rng.choice(values) for _ in values) / len(values) for _ in range(samples))
    return {
        "estimate": estimate,
        "lower_95": draws[int(samples * 0.025)],
        "upper_95": draws[min(samples - 1, int(samples * 0.975))],
    }


def _write_report(tag: str, split: str, model: str, adapter: Path, records: list[dict[str, Any]], rows: list[dict[str, Any]], bootstrap_samples: int, batch_size: int) -> dict[str, Any]:
    keys = (
        "json_valid",
        "schema_valid",
        "finding_id_exact",
        "summary_nonempty",
        "relevant_file_only",
        "patch_applies",
        "patched_code_parseable",
        "patched_code_exact",
        "security_control_pass",
        "no_dangerous_regression",
    )
    per_cwe = {}
    for cwe in sorted({record["cwe"] for record in records}):
        subset = [row for row in rows if row["cwe"] == cwe]
        per_cwe[cwe] = {
            "count": len(subset),
            "patch_apply_rate": _mean(subset, "patch_applies"),
            "control_pass_rate": _mean(subset, "security_control_pass"),
            "exact_patch_rate": _mean(subset, "patched_code_exact"),
        }
    metrics = {f"{key}_rate": _mean(rows, key) for key in keys}
    metrics["count"] = len(rows)
    metrics["latency_seconds"] = {
        "mean": statistics.fmean(row["latency_seconds"] for row in rows),
        "median": statistics.median(row["latency_seconds"] for row in rows),
    }
    metrics["confidence_intervals"] = {
        key: _bootstrap(rows, key, bootstrap_samples)
        for key in ("schema_valid", "patch_applies", "security_control_pass", "patched_code_exact")
    }
    metrics["per_cwe"] = per_cwe
    report = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "status": "complete",
        "tag": tag,
        "split": split,
        "model": model,
        "adapter": str(adapter),
        "adapter_sha256": _sha256_tree(adapter),
        "dataset_sha256": _sha256_file(_split_path(split)),
        "seed": SEED,
        "batch_size": batch_size,
        "metrics": metrics,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"eval_{tag}_repo_{split}.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        f"# {tag} Repository Patch Evaluation: {split}",
        "",
        f"- Records: {len(rows)}",
        f"- Strict schema: {metrics['schema_valid_rate']:.4f}",
        f"- Patch applies: {metrics['patch_applies_rate']:.4f}",
        f"- Security control: {metrics['security_control_pass_rate']:.4f}",
        f"- Exact patched code: {metrics['patched_code_exact_rate']:.4f}",
        f"- Relevant file only: {metrics['relevant_file_only_rate']:.4f}",
        "",
    ]
    (RESULTS_DIR / f"eval_{tag}_repo_{split}.md").write_text("\n".join(lines), encoding="utf-8")
    return report


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    records = _read_records(args.split, args.limit)
    adapter = args.adapter if args.adapter.is_absolute() else (PROJECT_DIR / args.adapter).resolve()
    predictions = RESULTS_DIR / f"eval_{args.tag}_repo_{args.split}.predictions.jsonl"
    if args.force:
        predictions.unlink(missing_ok=True)
    rows = [json.loads(line) for line in predictions.read_text(encoding="utf-8").splitlines()] if predictions.is_file() else []
    rows_by_id = {row["id"]: row for row in rows}
    pending = [record for record in records if record["id"] not in rows_by_id]
    runtime = TransformersRepairModel(args.model, str(adapter), args.max_seq_len)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with predictions.open("a", encoding="utf-8", newline="\n") as handle:
        for offset in range(0, len(pending), args.batch_size):
            batch = pending[offset : offset + args.batch_size]
            started = time.perf_counter()
            outputs = runtime.infer_batch([record["prompt"] for record in batch], args.max_new_tokens)
            elapsed = time.perf_counter() - started
            for record, output in zip(batch, outputs):
                row = {
                    "id": record["id"],
                    "cwe": record["cwe"],
                    "split": args.split,
                    "invalid_json": output["invalid_json"],
                    "output": output["output"],
                    "raw_output": output["raw_output"],
                    "error": output.get("json_error"),
                    "latency_seconds": elapsed / len(batch),
                }
                row["scores"] = _score(record, row)
                rows_by_id[row["id"]] = row
                handle.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")
            handle.flush()
            print(f"[{args.tag}/repo/{args.split}] {len(rows_by_id)}/{len(records)}", flush=True)
    ordered = [rows_by_id[record["id"]] for record in records]
    return _write_report(args.tag, args.split, args.model, adapter, records, ordered, args.bootstrap_samples, args.batch_size)


def self_test() -> dict[str, Any]:
    records = _read_records("test", 100)
    rows = []
    for record in records:
        inference = {"invalid_json": False, "output": record["target"], "raw_output": ""}
        rows.append({"id": record["id"], "cwe": record["cwe"], "latency_seconds": 0.0, "scores": _score(record, inference)})
    checks = {
        "schema": _mean(rows, "schema_valid") == 1.0,
        "patch_applies": _mean(rows, "patch_applies") == 1.0,
        "control": _mean(rows, "security_control_pass") == 1.0,
        "exact": _mean(rows, "patched_code_exact") == 1.0,
    }
    result = {"generated_at": _utc_now(), "status": "pass" if all(checks.values()) else "fail", "records": len(rows), "checks": checks}
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "v2_repo_evaluator_self_test.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if result["status"] != "pass":
        raise RuntimeError("repository evaluator self-test failed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate v2 repository-patch outputs.")
    parser.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    parser.add_argument("--adapter", type=Path, default=Path("adapters/pysecpatch-v2"))
    parser.add_argument("--tag", default="pysecpatch-v2")
    parser.add_argument("--split", choices=("test", "holdout"), default="test")
    parser.add_argument("--confirm-holdout", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-new-tokens", type=int, default=900)
    parser.add_argument("--max-seq-len", type=int, default=2048)
    parser.add_argument("--bootstrap-samples", type=int, default=2000)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.split == "holdout" and not args.confirm_holdout:
        parser.error("--split holdout requires --confirm-holdout")
    try:
        result = self_test() if args.self_test else evaluate(args)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
