"""Reproducible, resumable evaluation for PySecPatch repair models."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import io
import json
import math
import os
import platform
import random
import re
import statistics
import sys
import time
import tokenize
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from agent import SecurityVisitor
from data import SPECS
from models import TransformersRepairModel


PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
RESULTS_DIR = PROJECT_DIR / "results"
CONFIG_PATH = PROJECT_DIR / "config.yaml"
AUDIT_PATH = RESULTS_DIR / "license_audit.json"
DEFAULT_ADAPTER = PROJECT_DIR / "adapters/pysecpatch-v2"
SEED = 20260627
TARGET_FIELDS = (
    "is_vulnerable",
    "cwe",
    "vuln_type",
    "vulnerable_lines",
    "explanation",
    "fixed_code",
    "patch_summary",
    "safe_test",
)
IGNORED_TOKENS = {
    tokenize.ENCODING,
    tokenize.ENDMARKER,
    tokenize.INDENT,
    tokenize.DEDENT,
    tokenize.NEWLINE,
    tokenize.NL,
    tokenize.COMMENT,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected a JSON object: {path}")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _load_config() -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required; install requirements.txt.") from exc
    config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise RuntimeError(f"Invalid configuration: {CONFIG_PATH}")
    return config


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_tree(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(_sha256_file(item).encode("ascii"))
    return digest.hexdigest()


def _split_path(split: str) -> Path:
    return DATA_DIR / f"v2_{split}.jsonl"


def _read_split(split: str) -> list[dict[str, Any]]:
    path = _split_path(split)
    if not path.is_file():
        raise RuntimeError(f"Missing dataset split: {path}")
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    if not records or any(record.get("split") != split for record in records):
        raise RuntimeError(f"Invalid dataset split: {path}")
    analysis_records = [record for record in records if record.get("task") in {"detect", "repair"}]
    if not analysis_records:
        raise RuntimeError(f"No v2 detection/repair records in dataset split: {path}")
    return analysis_records


def _stratified_sample(records: list[dict[str, Any]], limit: int | None, seed: int) -> list[dict[str, Any]]:
    if limit is None or limit <= 0 or limit >= len(records):
        return records
    groups: dict[tuple[str, bool], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[(record["cwe"], bool(record["is_vulnerable"]))].append(record)
    rng = random.Random(seed)
    for values in groups.values():
        rng.shuffle(values)
    selected: list[dict[str, Any]] = []
    ordered = sorted(groups)
    while len(selected) < limit:
        changed = False
        for key in ordered:
            if groups[key] and len(selected) < limit:
                selected.append(groups[key].pop())
                changed = True
        if not changed:
            break
    return selected


def _prompt(record: dict[str, Any]) -> str:
    if isinstance(record.get("prompt"), str) and record["prompt"]:
        return record["prompt"]
    fields = "\n".join(TARGET_FIELDS)
    return (
        "Analyze this Python code and return exactly one JSON object with these fields:\n"
        f"{fields}\n\n"
        "Do not include markdown or surrounding text. Produce the smallest defensive repair.\n\n"
        f"Python code:\n{record['vulnerable_code']}"
    )


def _normalized_code(code: str) -> str | None:
    try:
        values = [
            f"{token.type}:{token.string}"
            for token in tokenize.generate_tokens(io.StringIO(code).readline)
            if token.type not in IGNORED_TOKENS
        ]
    except (IndentationError, tokenize.TokenError):
        return None
    return "\n".join(values)


class _StructureNormalizer(ast.NodeTransformer):
    def visit_Name(self, node: ast.Name) -> ast.AST:
        return ast.copy_location(ast.Name(id="VAR", ctx=node.ctx), node)

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = "ARG"
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.name = "FUNC"
        return self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.name = "CLASS"
        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str):
            value: Any = "<STR>"
        elif isinstance(node.value, bytes):
            value = b"<BYTES>"
        elif isinstance(node.value, bool) or node.value is None:
            value = node.value
        elif isinstance(node.value, (int, float, complex)):
            value = 0
        else:
            value = "<CONST>"
        return ast.copy_location(ast.Constant(value=value), node)


def _structural_code(code: str) -> str | None:
    try:
        tree = _StructureNormalizer().visit(ast.parse(code))
    except SyntaxError:
        return None
    return ast.dump(tree, include_attributes=False)


def _parseable(code: Any) -> bool:
    if not isinstance(code, str):
        return False
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def _changed_lines(before: str, after: str) -> int:
    import difflib

    changed = 0
    for tag, start, end, fixed_start, fixed_end in difflib.SequenceMatcher(
        None, before.splitlines(), after.splitlines()
    ).get_opcodes():
        if tag != "equal":
            changed += max(end - start, fixed_end - fixed_start)
    return changed


def _line_f1(expected: list[int], predicted: Any) -> float:
    if not isinstance(predicted, list) or any(type(item) is not int for item in predicted):
        return 0.0
    expected_set, predicted_set = set(expected), set(predicted)
    if not expected_set and not predicted_set:
        return 1.0
    if not expected_set or not predicted_set:
        return 0.0
    intersection = len(expected_set & predicted_set)
    precision = intersection / len(predicted_set)
    recall = intersection / len(expected_set)
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def _schema_valid(output: Any) -> bool:
    if not isinstance(output, dict) or set(output) != set(TARGET_FIELDS):
        return False
    return (
        type(output["is_vulnerable"]) is bool
        and isinstance(output["cwe"], str)
        and isinstance(output["vuln_type"], str)
        and isinstance(output["vulnerable_lines"], list)
        and all(type(item) is int for item in output["vulnerable_lines"])
        and isinstance(output["explanation"], str)
        and isinstance(output["fixed_code"], str)
        and isinstance(output["patch_summary"], str)
        and isinstance(output["safe_test"], str)
    )


def _spec_for_family(family: str) -> Any | None:
    return next((spec for spec in SPECS if f"-{spec.slug}-" in family), None)


def _finding_counts(code: str) -> Counter[str]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return Counter()
    visitor = SecurityVisitor("snippet.py", code)
    visitor.visit(tree)
    return Counter(finding["check"] for finding in visitor.findings)


def _score_one(reference: dict[str, Any], prediction: dict[str, Any]) -> dict[str, Any]:
    output = prediction.get("output")
    valid_schema = _schema_valid(output)
    scores: dict[str, Any] = {
        "json_valid": not prediction.get("invalid_json", True),
        "schema_valid": valid_schema,
        "classification_correct": False,
        "cwe_correct": False,
        "fixed_code_parseable": False,
        "safe_test_parseable": False,
        "fixed_normalized_exact": False,
        "fixed_structural_exact": False,
        "security_control_pass": False,
        "no_dangerous_regression": False,
        "negative_preserved": False,
        "line_f1": 0.0,
        "predicted_changed_lines": None,
        "reference_changed_lines": _changed_lines(reference["vulnerable_code"], reference["fixed_code"]),
        "overpatch": False,
    }
    if not valid_schema:
        return scores

    assert isinstance(output, dict)
    scores["classification_correct"] = output["is_vulnerable"] == reference["is_vulnerable"]
    scores["cwe_correct"] = output["cwe"].strip().upper() == reference["cwe"].upper()
    scores["line_f1"] = _line_f1(reference["vulnerable_lines"], output["vulnerable_lines"])
    scores["fixed_code_parseable"] = _parseable(output["fixed_code"])
    scores["safe_test_parseable"] = _parseable(output["safe_test"])
    normalized_prediction = _normalized_code(output["fixed_code"])
    normalized_reference = _normalized_code(reference["fixed_code"])
    scores["fixed_normalized_exact"] = (
        normalized_prediction is not None and normalized_prediction == normalized_reference
    )
    structure_prediction = _structural_code(output["fixed_code"])
    structure_reference = _structural_code(reference["fixed_code"])
    scores["fixed_structural_exact"] = (
        structure_prediction is not None and structure_prediction == structure_reference
    )
    changed = _changed_lines(reference["vulnerable_code"], output["fixed_code"])
    scores["predicted_changed_lines"] = changed
    if reference["is_vulnerable"]:
        reference_changed = max(1, scores["reference_changed_lines"])
        scores["overpatch"] = changed > max(reference_changed * 2, reference_changed + 5)
    else:
        scores["negative_preserved"] = (
            normalized_prediction == _normalized_code(reference["vulnerable_code"])
        )
        scores["overpatch"] = not scores["negative_preserved"]

    spec = _spec_for_family(reference["family"])
    control_pass = scores["fixed_code_parseable"] and spec is not None
    if control_pass and spec.forbidden_test_text:
        control_pass = spec.forbidden_test_text not in output["fixed_code"]
    if control_pass and spec.required_test_text:
        control_pass = spec.required_test_text in output["fixed_code"]
    scores["security_control_pass"] = bool(control_pass)

    before = _finding_counts(reference["vulnerable_code"])
    after = _finding_counts(output["fixed_code"])
    scores["no_dangerous_regression"] = all(after[key] <= before[key] for key in after)
    return scores


def _rate(rows: Iterable[dict[str, Any]], key: str) -> float:
    values = [float(bool(row[key])) for row in rows]
    return sum(values) / len(values) if values else 0.0


def _classification(rows: list[dict[str, Any]], references: dict[str, dict[str, Any]]) -> dict[str, Any]:
    tp = tn = fp = fn = 0
    for row in rows:
        expected = bool(references[row["id"]]["is_vulnerable"])
        output = row.get("output")
        predicted = output.get("is_vulnerable") if _schema_valid(output) else None
        if expected and predicted is True:
            tp += 1
        elif not expected and predicted is False:
            tn += 1
        elif not expected:
            fp += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denominator if denominator else 0.0
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2,
        "f1": f1,
        "mcc": mcc,
    }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _bootstrap_ci(
    rows: list[dict[str, Any]], key: str, samples: int, seed: int
) -> dict[str, float]:
    if not rows:
        return {"estimate": 0.0, "lower_95": 0.0, "upper_95": 0.0}
    rng = random.Random(seed)
    estimates = []
    for _ in range(samples):
        estimates.append(
            sum(float(bool(rows[rng.randrange(len(rows))]["scores"][key])) for _ in rows)
            / len(rows)
        )
    return {
        "estimate": _rate((row["scores"] for row in rows), key),
        "lower_95": _percentile(estimates, 0.025),
        "upper_95": _percentile(estimates, 0.975),
    }


def _environment() -> dict[str, Any]:
    versions = {}
    for package in ("torch", "transformers", "peft", "trl", "bitsandbytes"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    hardware: dict[str, Any] = {}
    try:
        import torch

        hardware["cuda_available"] = torch.cuda.is_available()
        if torch.cuda.is_available():
            index = torch.cuda.current_device()
            properties = torch.cuda.get_device_properties(index)
            hardware.update(
                {
                    "cuda_device": index,
                    "gpu_name": properties.name,
                    "gpu_vram_bytes": properties.total_memory,
                    "cuda_runtime": torch.version.cuda,
                }
            )
    except ImportError:
        hardware["cuda_available"] = False
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "cuda_visible_devices": os.getenv("CUDA_VISIBLE_DEVICES"),
        "packages": versions,
        "hardware": hardware,
    }


def _aggregate(
    rows: list[dict[str, Any]], records: list[dict[str, Any]], bootstrap_samples: int
) -> dict[str, Any]:
    references = {record["id"]: record for record in records}
    vulnerable = [row for row in rows if references[row["id"]]["is_vulnerable"]]
    negatives = [row for row in rows if not references[row["id"]]["is_vulnerable"]]
    latencies = [float(row.get("latency_seconds", 0.0)) for row in rows]
    per_cwe: dict[str, Any] = {}
    for cwe in sorted({record["cwe"] for record in records}):
        subset = [row for row in rows if references[row["id"]]["cwe"] == cwe]
        vulnerable_subset = [row for row in subset if references[row["id"]]["is_vulnerable"]]
        per_cwe[cwe] = {
            "count": len(subset),
            "classification_accuracy": _rate((row["scores"] for row in subset), "classification_correct"),
            "security_control_pass_rate": _rate(
                (row["scores"] for row in vulnerable_subset), "security_control_pass"
            ),
            "fixed_code_parse_rate": _rate(
                (row["scores"] for row in vulnerable_subset), "fixed_code_parseable"
            ),
        }
    return {
        "count": len(rows),
        "vulnerable_count": len(vulnerable),
        "negative_count": len(negatives),
        "strict_json_rate": _rate((row["scores"] for row in rows), "json_valid"),
        "schema_valid_rate": _rate((row["scores"] for row in rows), "schema_valid"),
        "classification": _classification(rows, references),
        "vulnerable_repair": {
            "cwe_exact_rate": _rate((row["scores"] for row in vulnerable), "cwe_correct"),
            "line_f1_mean": statistics.fmean(row["scores"]["line_f1"] for row in vulnerable)
            if vulnerable
            else 0.0,
            "fixed_code_parse_rate": _rate(
                (row["scores"] for row in vulnerable), "fixed_code_parseable"
            ),
            "safe_test_parse_rate": _rate(
                (row["scores"] for row in vulnerable), "safe_test_parseable"
            ),
            "normalized_exact_rate": _rate(
                (row["scores"] for row in vulnerable), "fixed_normalized_exact"
            ),
            "structural_exact_rate": _rate(
                (row["scores"] for row in vulnerable), "fixed_structural_exact"
            ),
            "security_control_pass_rate": _rate(
                (row["scores"] for row in vulnerable), "security_control_pass"
            ),
            "no_dangerous_regression_rate": _rate(
                (row["scores"] for row in vulnerable), "no_dangerous_regression"
            ),
            "overpatch_rate": _rate((row["scores"] for row in vulnerable), "overpatch"),
        },
        "clean_negative": {
            "preservation_rate": _rate((row["scores"] for row in negatives), "negative_preserved"),
            "overpatch_rate": _rate((row["scores"] for row in negatives), "overpatch"),
        },
        "latency_seconds": {
            "mean": statistics.fmean(latencies) if latencies else 0.0,
            "median": statistics.median(latencies) if latencies else 0.0,
            "p95": _percentile(latencies, 0.95),
        },
        "confidence_intervals": {
            "json_valid": _bootstrap_ci(rows, "json_valid", bootstrap_samples, SEED),
            "classification_correct": _bootstrap_ci(
                rows, "classification_correct", bootstrap_samples, SEED + 1
            ),
            "security_control_pass": _bootstrap_ci(
                vulnerable, "security_control_pass", bootstrap_samples, SEED + 2
            ),
            "no_dangerous_regression": _bootstrap_ci(
                vulnerable, "no_dangerous_regression", bootstrap_samples, SEED + 3
            ),
            "negative_preserved": _bootstrap_ci(
                negatives, "negative_preserved", bootstrap_samples, SEED + 4
            ),
        },
        "per_cwe": per_cwe,
    }


def _safe_tag(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-").lower()


def _audit_model(model_id: str) -> dict[str, Any]:
    audit = _load_json(AUDIT_PATH)
    audit_id = model_id
    model_path = Path(model_id)
    if model_path.is_dir():
        metadata_path = model_path / "merge_metadata.json"
        if not metadata_path.is_file():
            raise RuntimeError(
                f"Local model {model_id!r} lacks merge_metadata.json; its base license cannot be verified."
            )
        metadata = _load_json(metadata_path)
        audit_id = str(metadata.get("base_model", ""))
        if not audit_id:
            raise RuntimeError(f"Local model metadata does not identify a base model: {metadata_path}")
    record = next((item for item in audit.get("models", []) if item.get("model_id") == audit_id), None)
    if not record or record.get("status") not in {"train_allowed", "baseline_only"}:
        status = record.get("status") if record else "not_audited"
        raise RuntimeError(f"Model base {audit_id!r} is not approved for evaluation (status={status}).")
    return {**record, "evaluated_model": model_id, "audited_model": audit_id}


def _load_predictions(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _report_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    classification = metrics["classification"]
    repair = metrics["vulnerable_repair"]
    negative = metrics["clean_negative"]
    lines = [
        f"# Evaluation: {report['tag']} on {report['split']}",
        "",
        f"- Model: `{report['model_id']}`",
        f"- Adapter: `{report.get('adapter_path') or 'none'}`",
        f"- Records: {metrics['count']}",
        f"- Inference batch size: {report.get('batch_size', 1)}",
        f"- Dataset SHA-256: `{report['dataset_sha256']}`",
        "",
        "## Core Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Strict JSON | {metrics['strict_json_rate']:.4f} |",
        f"| Schema valid | {metrics['schema_valid_rate']:.4f} |",
        f"| Classification accuracy | {classification['accuracy']:.4f} |",
        f"| Classification F1 | {classification['f1']:.4f} |",
        f"| Matthews correlation | {classification['mcc']:.4f} |",
        f"| CWE exact | {repair['cwe_exact_rate']:.4f} |",
        f"| Fixed code parses | {repair['fixed_code_parse_rate']:.4f} |",
        f"| Security control pass | {repair['security_control_pass_rate']:.4f} |",
        f"| Dangerous-regression free | {repair['no_dangerous_regression_rate']:.4f} |",
        f"| Vulnerable overpatch rate | {repair['overpatch_rate']:.4f} |",
        f"| Clean negative preservation | {negative['preservation_rate']:.4f} |",
        f"| Median latency (seconds) | {metrics['latency_seconds']['median']:.4f} |",
        "",
        "## CWE Breakdown",
        "",
        "| CWE | N | Classification | Control pass | Parse rate |",
        "|---|---:|---:|---:|---:|",
    ]
    for cwe, values in metrics["per_cwe"].items():
        lines.append(
            f"| {cwe} | {values['count']} | {values['classification_accuracy']:.4f} | "
            f"{values['security_control_pass_rate']:.4f} | {values['fixed_code_parse_rate']:.4f} |"
        )
    lines.extend(("", "Generated code was parsed and inspected statically; it was not executed.", ""))
    return "\n".join(lines)


def _evaluate_variant(
    model_id: str,
    adapter_path: Path | None,
    split: str,
    limit: int | None,
    tag: str,
    max_new_tokens: int,
    bootstrap_samples: int,
    force: bool,
    batch_size: int,
) -> dict[str, Any]:
    audit_record = _audit_model(model_id)
    random.seed(SEED)
    try:
        import torch

        torch.manual_seed(SEED)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(SEED)
    except ImportError:
        pass
    config = _load_config()
    records = _stratified_sample(_read_split(split), limit, SEED)
    prediction_path = RESULTS_DIR / f"eval_{tag}_{split}.predictions.jsonl"
    if force and prediction_path.exists():
        prediction_path.unlink()
    rows = _load_predictions(prediction_path)
    completed = {row["id"] for row in rows}
    references = {record["id"]: record for record in records}
    rows = [row for row in rows if row.get("id") in references]
    runtime = TransformersRepairModel(
        model_id,
        str(adapter_path) if adapter_path else None,
        int(config.get("max_seq_len", 4096)),
    )
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    pending = [record for record in records if record["id"] not in completed]
    processed = len(records) - len(pending)
    with prediction_path.open("a", encoding="utf-8", newline="\n") as handle:
        for offset in range(0, len(pending), batch_size):
            batch = pending[offset : offset + batch_size]
            started = time.perf_counter()
            try:
                inferences = runtime.infer_batch(
                    [_prompt(record) for record in batch], max_new_tokens=max_new_tokens
                )
            except Exception as exc:
                if "out of memory" in str(exc).lower() and batch_size > 1:
                    raise RuntimeError(
                        f"Batch size {batch_size} exhausted GPU memory; retry with a smaller --batch-size."
                    ) from exc
                inferences = [
                    {
                        "invalid_json": True,
                        "output": None,
                        "raw_output": "",
                        "json_error": f"{type(exc).__name__}: {exc}",
                    }
                    for _ in batch
                ]
            batch_elapsed = time.perf_counter() - started
            for record, inference in zip(batch, inferences):
                row = {
                    "id": record["id"],
                    "split": split,
                    "family": record["family"],
                    "invalid_json": inference["invalid_json"],
                    "output": inference["output"],
                    "raw_output": inference["raw_output"],
                    "error": inference.get("json_error"),
                    "latency_seconds": batch_elapsed / len(batch),
                    "batch_latency_seconds": batch_elapsed,
                    "batch_size": len(batch),
                }
                row["scores"] = _score_one(record, row)
                handle.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")
                rows.append(row)
                processed += 1
            handle.flush()
            print(f"[{tag}/{split}] {processed}/{len(records)}", flush=True)
    del runtime
    try:
        import torch

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except ImportError:
        pass
    rows_by_id = {row["id"]: row for row in rows}
    ordered_rows = [rows_by_id[record["id"]] for record in records]
    metrics = _aggregate(ordered_rows, records, bootstrap_samples)
    report = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "tag": tag,
        "model_id": model_id,
        "audited_base_model": audit_record["audited_model"],
        "model_license_status": audit_record["status"],
        "model_license": audit_record.get("license"),
        "adapter_path": str(adapter_path) if adapter_path else None,
        "adapter_sha256": _sha256_tree(adapter_path) if adapter_path else None,
        "split": split,
        "limit": limit,
        "batch_size": batch_size,
        "seed": SEED,
        "dataset_sha256": _sha256_file(_split_path(split)),
        "prediction_file": str(prediction_path),
        "environment": _environment(),
        "metrics": metrics,
    }
    json_path = RESULTS_DIR / f"eval_{tag}_{split}.json"
    _write_json(json_path, report)
    json_path.with_suffix(".md").write_text(_report_markdown(report), encoding="utf-8")
    return report


def _mcnemar_exact(left: list[bool], right: list[bool]) -> dict[str, Any]:
    left_only = sum(a and not b for a, b in zip(left, right))
    right_only = sum(b and not a for a, b in zip(left, right))
    discordant = left_only + right_only
    if discordant == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, value) for value in range(min(left_only, right_only) + 1))
        p_value = min(1.0, 2 * tail * (0.5**discordant))
    return {
        "left_only_correct": left_only,
        "right_only_correct": right_only,
        "discordant": discordant,
        "exact_two_sided_p": p_value,
    }


def _paired_effect(
    left_rows: dict[str, dict[str, Any]],
    right_rows: dict[str, dict[str, Any]],
    record_ids: list[str],
    metric: str,
    samples: int,
    seed: int,
) -> dict[str, float]:
    differences = [
        float(bool(right_rows[item]["scores"][metric]))
        - float(bool(left_rows[item]["scores"][metric]))
        for item in record_ids
    ]
    if not differences:
        return {"difference_right_minus_left": 0.0, "lower_95": 0.0, "upper_95": 0.0}
    rng = random.Random(seed)
    bootstrapped = [
        statistics.fmean(differences[rng.randrange(len(differences))] for _ in differences)
        for _ in range(samples)
    ]
    return {
        "difference_right_minus_left": statistics.fmean(differences),
        "lower_95": _percentile(bootstrapped, 0.025),
        "upper_95": _percentile(bootstrapped, 0.975),
    }


def _add_holm_adjustment(comparisons: list[dict[str, Any]]) -> None:
    ordered = sorted(
        enumerate(comparisons), key=lambda item: item[1]["mcnemar"]["exact_two_sided_p"]
    )
    running = 0.0
    count = len(ordered)
    for rank, (index, comparison) in enumerate(ordered):
        raw = comparison["mcnemar"]["exact_two_sided_p"]
        adjusted = min(1.0, raw * (count - rank))
        running = max(running, adjusted)
        comparisons[index]["mcnemar"]["holm_adjusted_p"] = running


def _benchmark_summary(skipped_models: list[dict[str, str]] | None = None) -> dict[str, Any]:
    reports = []
    for path in sorted(RESULTS_DIR.glob("eval_*.json")):
        if path.name == "benchmark_summary.json":
            continue
        try:
            reports.append(_load_json(path))
        except (OSError, json.JSONDecodeError, RuntimeError):
            continue
    prediction_sets: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for report in reports:
        prediction_path = Path(report["prediction_file"])
        prediction_sets[(report["tag"], report["split"])] = {
            row["id"]: row for row in _load_predictions(prediction_path)
        }
    comparisons = []
    paired_bootstrap_samples = 2000
    for index, left_report in enumerate(reports):
        for right_report in reports[index + 1 :]:
            if left_report["split"] != right_report["split"]:
                continue
            left_rows = prediction_sets.get((left_report["tag"], left_report["split"]), {})
            right_rows = prediction_sets.get((right_report["tag"], right_report["split"]), {})
            shared = sorted(set(left_rows) & set(right_rows))
            if not shared:
                continue
            references = {record["id"]: record for record in _read_split(left_report["split"])}
            vulnerable_ids = [item for item in shared if references[item]["is_vulnerable"]]
            negative_ids = [item for item in shared if not references[item]["is_vulnerable"]]
            left_correct = [bool(left_rows[item]["scores"]["classification_correct"]) for item in shared]
            right_correct = [bool(right_rows[item]["scores"]["classification_correct"]) for item in shared]
            comparisons.append(
                {
                    "left": left_report["tag"],
                    "right": right_report["tag"],
                    "split": left_report["split"],
                    "shared_records": len(shared),
                    "paired_effects": {
                        "strict_json": _paired_effect(
                            left_rows, right_rows, shared, "json_valid", paired_bootstrap_samples, SEED
                        ),
                        "classification_accuracy": _paired_effect(
                            left_rows,
                            right_rows,
                            shared,
                            "classification_correct",
                            paired_bootstrap_samples,
                            SEED + 1,
                        ),
                        "security_control_pass": _paired_effect(
                            left_rows,
                            right_rows,
                            vulnerable_ids,
                            "security_control_pass",
                            paired_bootstrap_samples,
                            SEED + 2,
                        ),
                        "no_dangerous_regression": _paired_effect(
                            left_rows,
                            right_rows,
                            vulnerable_ids,
                            "no_dangerous_regression",
                            paired_bootstrap_samples,
                            SEED + 3,
                        ),
                        "negative_preservation": _paired_effect(
                            left_rows,
                            right_rows,
                            negative_ids,
                            "negative_preserved",
                            paired_bootstrap_samples,
                            SEED + 4,
                        ),
                    },
                    "mcnemar": _mcnemar_exact(left_correct, right_correct),
                }
            )
    _add_holm_adjustment(comparisons)
    summary = {
        "generated_at": _utc_now(),
        "paired_bootstrap_samples": paired_bootstrap_samples,
        "reports": [
            {
                "tag": report["tag"],
                "split": report["split"],
                "count": report["metrics"]["count"],
                "json_rate": report["metrics"]["strict_json_rate"],
                "classification_f1": report["metrics"]["classification"]["f1"],
                "control_pass_rate": report["metrics"]["vulnerable_repair"][
                    "security_control_pass_rate"
                ],
                "negative_preservation": report["metrics"]["clean_negative"]["preservation_rate"],
            }
            for report in reports
        ],
        "paired_comparisons": comparisons,
        "skipped_models": skipped_models or [],
    }
    _write_json(RESULTS_DIR / "benchmark_summary.json", summary)
    lines = [
        "# Benchmark Summary",
        "",
        "| Tag | Split | N | JSON | Classification F1 | Control pass | Negative preservation |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for item in summary["reports"]:
        lines.append(
            f"| {item['tag']} | {item['split']} | {item['count']} | {item['json_rate']:.4f} | "
            f"{item['classification_f1']:.4f} | {item['control_pass_rate']:.4f} | "
            f"{item['negative_preservation']:.4f} |"
        )
    if summary["skipped_models"]:
        lines.extend(("", "## Skipped Models", ""))
        for item in summary["skipped_models"]:
            lines.append(f"- `{item['model_id']}`: {item['reason']}")
    if summary["paired_comparisons"]:
        lines.extend(
            (
                "",
                "## Paired Classification Comparisons",
                "",
                "| Left | Right | Split | N | Difference | 95% CI | McNemar p | Holm p |",
                "|---|---|---|---:|---:|---:|---:|---:|",
            )
        )
        for item in summary["paired_comparisons"]:
            effect = item["paired_effects"]["classification_accuracy"]
            test = item["mcnemar"]
            lines.append(
                f"| {item['left']} | {item['right']} | {item['split']} | "
                f"{item['shared_records']} | {effect['difference_right_minus_left']:.4f} | "
                f"[{effect['lower_95']:.4f}, {effect['upper_95']:.4f}] | "
                f"{test['exact_two_sided_p']:.6g} | {test['holm_adjusted_p']:.6g} |"
            )
    (RESULTS_DIR / "benchmark_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def _score_existing(path: Path, split: str, bootstrap_samples: int, tag: str) -> dict[str, Any]:
    records = _read_split(split)
    references = {record["id"]: record for record in records}
    rows = [row for row in _load_predictions(path) if row.get("id") in references]
    for row in rows:
        row["scores"] = _score_one(references[row["id"]], row)
    selected_records = [references[row["id"]] for row in rows]
    metrics = _aggregate(rows, selected_records, bootstrap_samples)
    report = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "tag": tag,
        "model_id": "scored-predictions",
        "adapter_path": None,
        "split": split,
        "limit": len(rows),
        "seed": SEED,
        "dataset_sha256": _sha256_file(_split_path(split)),
        "prediction_file": str(path),
        "metrics": metrics,
    }
    output = RESULTS_DIR / f"eval_{tag}_{split}.json"
    _write_json(output, report)
    output.with_suffix(".md").write_text(_report_markdown(report), encoding="utf-8")
    return report


def _self_test() -> dict[str, Any]:
    records = _stratified_sample(_read_split("test"), 100, SEED)
    rows = []
    for record in records:
        output = {field: record[field] for field in TARGET_FIELDS}
        prediction = {"invalid_json": False, "output": output}
        rows.append(
            {
                "id": record["id"],
                "invalid_json": False,
                "output": output,
                "latency_seconds": 0.0,
                "scores": _score_one(record, prediction),
            }
        )
    metrics = _aggregate(rows, records, 200)
    vulnerable = next(record for record in records if record["is_vulnerable"])
    malformed_scores = _score_one(vulnerable, {"invalid_json": True, "output": None})
    unsafe_output = {field: vulnerable[field] for field in TARGET_FIELDS}
    unsafe_output["fixed_code"] = "import os\n\ndef run(value):\n    return os.system(value)\n"
    unsafe_scores = _score_one(
        vulnerable, {"invalid_json": False, "output": unsafe_output}
    )
    checks = {
        "oracle_json_rate_is_one": metrics["strict_json_rate"] == 1.0,
        "oracle_schema_rate_is_one": metrics["schema_valid_rate"] == 1.0,
        "oracle_classification_is_one": metrics["classification"]["accuracy"] == 1.0,
        "oracle_control_pass_is_one": (
            metrics["vulnerable_repair"]["security_control_pass_rate"] == 1.0
        ),
        "oracle_negative_preservation_is_one": (
            metrics["clean_negative"]["preservation_rate"] == 1.0
        ),
        "malformed_output_rejected": not malformed_scores["schema_valid"],
        "introduced_danger_detected": not unsafe_scores["no_dangerous_regression"],
    }
    result = {
        "generated_at": _utc_now(),
        "status": "pass" if all(checks.values()) else "fail",
        "seed": SEED,
        "records": len(records),
        "checks": checks,
    }
    _write_json(RESULTS_DIR / "evaluator_v2_self_test.json", result)
    if result["status"] != "pass":
        raise RuntimeError("Evaluator self-test failed; inspect results/evaluator_v2_self_test.json.")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run reproducible PySecPatch static repair benchmarks.")
    parser.add_argument("--model", help="audited base model ID")
    parser.add_argument("--adapter", type=Path, help="optional LoRA adapter path")
    parser.add_argument("--tag", help="stable output tag")
    parser.add_argument("--split", choices=("test", "holdout"), default="test")
    parser.add_argument("--confirm-holdout", action="store_true", help="confirm the frozen holdout run")
    parser.add_argument("--limit", type=int, help="stratified record limit; 0 means the full split")
    parser.add_argument("--max-new-tokens", type=int, default=900)
    parser.add_argument("--batch-size", type=int, default=1, help="deterministic inference batch size")
    parser.add_argument("--bootstrap-samples", type=int, default=1000)
    parser.add_argument("--force", action="store_true", help="discard resumable predictions for this tag")
    parser.add_argument("--all", action="store_true", help="run every audited configured baseline on the selected split")
    parser.add_argument("--score", type=Path, help="score an existing prediction JSONL without inference")
    parser.add_argument("--summarize", action="store_true", help="rebuild the cross-model benchmark summary")
    parser.add_argument("--self-test", action="store_true", help="validate scorer invariants without a model")
    args = parser.parse_args()

    if args.split == "holdout" and not args.confirm_holdout:
        parser.error("--split holdout requires --confirm-holdout")
    if args.bootstrap_samples < 100:
        parser.error("--bootstrap-samples must be at least 100")
    if args.batch_size < 1:
        parser.error("--batch-size must be at least 1")
    if args.self_test:
        try:
            print(json.dumps(_self_test(), indent=2))
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            parser.exit(2, f"error: {exc}\n")
        return 0
    config = _load_config()
    limit = args.limit if args.limit is not None else int(config.get("eval_limit", 500))
    reports = []
    skipped_models: list[dict[str, str]] = []
    try:
        if args.score:
            reports.append(
                _score_existing(
                    args.score,
                    args.split,
                    args.bootstrap_samples,
                    _safe_tag(args.tag or args.score.stem),
                )
            )
        elif args.all:
            for model_id in config.get("baseline_models", []):
                try:
                    _audit_model(model_id)
                except RuntimeError as exc:
                    skipped_models.append({"model_id": model_id, "reason": str(exc)})
                    print(f"[skip] {exc}", file=sys.stderr, flush=True)
                    continue
                reports.append(
                    _evaluate_variant(
                        model_id,
                        None,
                        args.split,
                        limit,
                        _safe_tag(model_id),
                        args.max_new_tokens,
                        args.bootstrap_samples,
                        args.force,
                        args.batch_size,
                    )
                )
            if DEFAULT_ADAPTER.is_dir():
                reports.append(
                    _evaluate_variant(
                        str(config["base_model"]),
                        DEFAULT_ADAPTER,
                        args.split,
                        limit,
                        "pysecpatch-test-adapter",
                        args.max_new_tokens,
                        args.bootstrap_samples,
                        args.force,
                        args.batch_size,
                    )
                )
        elif args.model:
            model_id = args.model
            local_model = Path(model_id)
            if not local_model.is_absolute() and (PROJECT_DIR / local_model).is_dir():
                model_id = str((PROJECT_DIR / local_model).resolve())
            adapter = args.adapter
            if adapter and not adapter.is_absolute():
                adapter = (PROJECT_DIR / adapter).resolve()
            tag = _safe_tag(args.tag or ("pysecpatch-v2" if adapter else Path(model_id).name))
            reports.append(
                _evaluate_variant(
                    model_id,
                    adapter,
                    args.split,
                    limit,
                    tag,
                    args.max_new_tokens,
                    args.bootstrap_samples,
                    args.force,
                    args.batch_size,
                )
            )
        elif not args.summarize:
            parser.error("use --model, --all, --score, or --summarize")
        summary = _benchmark_summary(skipped_models)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(
        json.dumps(
            {
                "status": "complete",
                "reports": [f"{report['tag']}:{report['split']}" for report in reports],
                "benchmark_reports": len(summary["reports"]),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
