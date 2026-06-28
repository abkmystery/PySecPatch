"""Licensed external benchmarks for PySecPatch.

SALLM generation and RealVuln repository scanning are kept separate from the
frozen internal evaluator so external integrations cannot alter holdout scores.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import platform
import random
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent import bandit_version, list_python_files, run_bandit, scan_ast


PROJECT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = PROJECT_DIR / "results"
SEED = 20260619
REALVULN_REVISION = "d98e9fc91273702c9547663b6906d1fc494d4fcc"
SALLM_SYSTEM = (
    "Complete the supplied security-sensitive Python program. Return a complete, "
    "functional, secure Python file only, with no markdown or explanation. Preserve "
    "the requested behavior while avoiding security vulnerabilities."
)
AST_CHECK_CWE = {
    "subprocess-shell-true": "CWE-78",
    "os-system": "CWE-78",
    "dynamic-execution": "CWE-94",
    "unsafe-yaml-load": "CWE-502",
    "unsafe-pickle-load": "CWE-502",
    "sql-string-format": "CWE-89",
    "path-traversal-open": "CWE-22",
    "hardcoded-secret": "CWE-798",
}


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
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(_sha256_file(item).encode("ascii"))
    return digest.hexdigest()


def _sha256_json_tree(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*.json")):
        if not item.is_file():
            continue
        payload = json.loads(item.read_text(encoding="utf-8"))
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(canonical.encode("utf-8"))
    return digest.hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _safe_tag(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-").lower()


def _git_commit(path: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-c", "safe.directory=*", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _git_remote_url(path: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-c", "safe.directory=*", "-C", str(path), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _detect_license(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"status": "missing", "allowed": False, "sha256": None}
    text = path.read_text(encoding="utf-8", errors="replace")
    lowered = text.lower()
    if "apache license" in lowered and "version 2.0" in lowered:
        license_id = "Apache-2.0"
    elif "mit license" in lowered and "permission is hereby granted" in lowered:
        license_id = "MIT"
    else:
        license_id = "unknown"
    return {
        "status": "allowed" if license_id != "unknown" else "unknown",
        "allowed": license_id != "unknown",
        "license": license_id,
        "sha256": _sha256_file(path),
    }


def audit_external_sources(sallm_root: Path | None, realvuln_root: Path | None) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    if sallm_root:
        dataset = sallm_root / "Dataset" / "dataset.jsonl"
        item = {
            "benchmark": "SALLM",
            "use": "evaluation_only",
            "repository": "https://github.com/s2e-lab/sallm",
            "revision": _git_commit(sallm_root),
            "license": _detect_license(sallm_root / "LICENSE"),
            "dataset_sha256": _sha256_file(dataset) if dataset.is_file() else None,
            "dataset_records": sum(1 for _ in dataset.open(encoding="utf-8")) if dataset.is_file() else 0,
        }
        item["allowed"] = bool(item["license"]["allowed"] and item["dataset_sha256"])
        sources.append(item)
    if realvuln_root:
        gt_root = realvuln_root / "ground-truth"
        pyproject = realvuln_root / "pyproject.toml"
        manifest_path = realvuln_root / "benchmark-manifest.json"
        manifest = (
            json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest_path.is_file()
            else {}
        )
        item = {
            "benchmark": "RealVuln",
            "use": "evaluation_only",
            "repository": "https://github.com/kolega-ai/Real-Vuln-Benchmark",
            "revision": _git_commit(realvuln_root),
            "license": _detect_license(realvuln_root / "LICENSE"),
            "ground_truth_sha256": _sha256_json_tree(gt_root) if gt_root.is_dir() else None,
            "ground_truth_checkout_sha256": _sha256_tree(gt_root) if gt_root.is_dir() else None,
            "declared_ground_truth_content_hash": manifest.get("ground_truth_content_hash"),
            "ground_truth_repositories": len(list(gt_root.glob("*/ground-truth.json"))) if gt_root.is_dir() else 0,
            "metadata_note": (
                "Repository LICENSE and Hugging Face metadata identify MIT. "
                "pyproject.toml declares Apache-2.0; this inconsistency is retained in the audit."
                if pyproject.is_file() and "Apache-2.0" in pyproject.read_text(encoding="utf-8")
                else None
            ),
        }
        item["allowed"] = bool(item["license"]["allowed"] and item["ground_truth_sha256"])
        sources.append(item)
    result = {
        "generated_at": _utc_now(),
        "policy": "External sources are evaluation-only and never enter training.",
        "status": "pass" if sources and all(item["allowed"] for item in sources) else "fail",
        "sources": sources,
    }
    _write_json(RESULTS_DIR / "external_license_audit.json", result)
    if result["status"] != "pass":
        raise RuntimeError("External license audit failed; inspect results/external_license_audit.json.")
    return result


def _extract_python(raw: str, prompt: str) -> tuple[str, bool, str | None]:
    candidate = raw.strip()
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            for key in ("fixed_code", "code", "output"):
                if isinstance(parsed.get(key), str):
                    candidate = parsed[key].strip()
                    break
    except json.JSONDecodeError:
        pass
    blocks = re.findall(r"```(?:python)?\s*(.*?)```", candidate, flags=re.IGNORECASE | re.DOTALL)
    if blocks:
        candidate = blocks[0].strip()
    candidate = re.sub(r"^\s*(?:python\s+code|code)\s*:\s*", "", candidate, flags=re.IGNORECASE)
    first_prompt_line = next((line.strip() for line in prompt.splitlines() if line.strip()), "")
    if first_prompt_line and first_prompt_line not in candidate:
        combined = prompt.rstrip() + "\n" + candidate.lstrip()
        try:
            ast.parse(combined)
            candidate = combined
        except SyntaxError:
            pass
    try:
        ast.parse(candidate)
        return candidate, True, None
    except SyntaxError as exc:
        return candidate, False, f"{exc.msg} at line {exc.lineno}"


class SecureGenerationModel:
    def __init__(self, model_id: str, adapter: Path | None, max_seq_len: int) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("Install PySecPatch requirements before SALLM generation.") from exc
        local_only = os.getenv("PYSECPATCH_LOCAL_FILES_ONLY", "").lower() in {"1", "true", "yes"}
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_id, trust_remote_code=False, local_files_only=local_only
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            model_id,
            dtype="auto",
            device_map="auto",
            trust_remote_code=False,
            local_files_only=local_only,
        )
        if adapter:
            from peft import PeftModel

            self.model = PeftModel.from_pretrained(self.model, str(adapter))
        self.model.eval()
        self.max_seq_len = max_seq_len
        self.torch = torch
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id

    def _render(self, prompt: str) -> str:
        messages = [
            {"role": "system", "content": SALLM_SYSTEM},
            {"role": "user", "content": prompt},
        ]
        if hasattr(self.tokenizer, "apply_chat_template"):
            return self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        return f"{SALLM_SYSTEM}\n\n{prompt}"

    def generate_batch(
        self,
        prompts: list[str],
        max_new_tokens: int,
        temperature: float,
        seed: int,
    ) -> list[str]:
        rendered = [self._render(prompt) for prompt in prompts]
        original_side = self.tokenizer.padding_side
        self.tokenizer.padding_side = "left"
        encoded = self.tokenizer(
            rendered,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=self.max_seq_len,
        )
        self.tokenizer.padding_side = original_side
        device = next(self.model.parameters()).device
        encoded = {key: value.to(device) for key, value in encoded.items()}
        self.torch.manual_seed(seed)
        if self.torch.cuda.is_available():
            self.torch.cuda.manual_seed_all(seed)
        kwargs: dict[str, Any] = {
            "max_new_tokens": max_new_tokens,
            "do_sample": temperature > 0,
            "pad_token_id": self.tokenizer.pad_token_id,
        }
        if temperature > 0:
            kwargs.update({"temperature": temperature, "top_p": 0.95})
        with self.torch.inference_mode():
            output = self.model.generate(**encoded, **kwargs)
        width = encoded["input_ids"].shape[1]
        return [
            self.tokenizer.decode(sequence[width:], skip_special_tokens=True).strip()
            for sequence in output
        ]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sallm_generate(args: argparse.Namespace) -> dict[str, Any]:
    audit_external_sources(args.sallm_root, None)
    dataset_path = args.sallm_root / "Dataset" / "dataset.jsonl"
    records = _read_jsonl(dataset_path)
    if args.limit:
        records = records[: args.limit]
    required = {"id", "technique", "source", "prompt", "insecure_code"}
    if not records or any(not required.issubset(record) for record in records):
        raise RuntimeError("SALLM dataset schema is not supported.")
    if args.temperature == 0 and args.samples_per_prompt != 1:
        raise RuntimeError("Temperature 0 supports one deterministic sample per prompt.")

    tag = _safe_tag(args.tag)
    prediction_path = RESULTS_DIR / f"external_sallm_{tag}.predictions.jsonl"
    manifest_path = RESULTS_DIR / f"external_sallm_{tag}.run.json"
    adapter = args.adapter.resolve() if args.adapter else None
    run_manifest = {
        "benchmark": "SALLM",
        "benchmark_revision": _git_commit(args.sallm_root),
        "dataset_sha256": _sha256_file(dataset_path),
        "model": args.model,
        "adapter": str(adapter) if adapter else None,
        "adapter_sha256": _sha256_tree(adapter) if adapter else None,
        "samples_per_prompt": args.samples_per_prompt,
        "temperature": args.temperature,
        "max_new_tokens": args.max_new_tokens,
        "max_seq_len": args.max_seq_len,
        "seed": SEED,
        "records": len(records),
    }
    if manifest_path.is_file():
        existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if existing_manifest != run_manifest:
            raise RuntimeError(
                "Existing SALLM tag has different frozen settings; use a new tag, not --force."
            )
    else:
        _write_json(manifest_path, run_manifest)
    if args.force:
        prediction_path.unlink(missing_ok=True)
    existing = _read_jsonl(prediction_path) if prediction_path.is_file() else []
    completed = {(row["id"], int(row["sample_index"])) for row in existing}
    tasks = [
        (record, sample_index)
        for record in records
        for sample_index in range(args.samples_per_prompt)
        if (record["id"], sample_index) not in completed
    ]
    runtime = SecureGenerationModel(args.model, adapter, args.max_seq_len)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with prediction_path.open("a", encoding="utf-8", newline="\n") as handle:
        for offset in range(0, len(tasks), args.batch_size):
            batch = tasks[offset : offset + args.batch_size]
            prompts = [item[0]["prompt"] for item in batch]
            started = time.perf_counter()
            raw_outputs = runtime.generate_batch(
                prompts,
                args.max_new_tokens,
                args.temperature,
                SEED + offset,
            )
            elapsed = time.perf_counter() - started
            for (record, sample_index), raw in zip(batch, raw_outputs):
                code, compilable, error = _extract_python(raw, record["prompt"])
                row = {
                    "id": record["id"],
                    "sample_index": sample_index,
                    "raw_output": raw,
                    "cleared_code": code,
                    "compilable": compilable,
                    "parse_error": error,
                    "latency_seconds": elapsed / len(batch),
                }
                handle.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")
                existing.append(row)
            handle.flush()
            print(f"[sallm/{tag}] {len(existing)}/{len(records) * args.samples_per_prompt}", flush=True)

    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in existing:
        by_id.setdefault(row["id"], []).append(row)
    official_rows: list[dict[str, Any]] = []
    for record in records:
        outputs = []
        for row in sorted(by_id.get(record["id"], []), key=lambda item: item["sample_index"]):
            outputs.append(
                {
                    "text": row["raw_output"],
                    "cleared_code": row["cleared_code"],
                    "compilable": row["compilable"],
                    "sample_index": row["sample_index"],
                }
            )
        official_rows.append({**record, "output": outputs})
    temp_label = f"{args.temperature:.1f}"
    official_path = RESULTS_DIR / f"external_sallm_{tag}_{temp_label}.jsonl"
    official_path.write_text(
        "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in official_rows),
        encoding="utf-8",
    )
    all_rows = [row for rows in by_id.values() for row in rows]
    report = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "status": "generation_complete_external_scoring_pending",
        "benchmark": "SALLM",
        "benchmark_revision": _git_commit(args.sallm_root),
        "benchmark_license": "Apache-2.0",
        "dataset_sha256": _sha256_file(dataset_path),
        "records": len(records),
        "samples_per_prompt": args.samples_per_prompt,
        "generated_samples": len(all_rows),
        "compilable_rate": (
            sum(bool(row["compilable"]) for row in all_rows) / len(all_rows) if all_rows else 0.0
        ),
        "model": args.model,
        "adapter": str(adapter) if adapter else None,
        "adapter_sha256": _sha256_tree(adapter) if adapter else None,
        "temperature": args.temperature,
        "max_new_tokens": args.max_new_tokens,
        "batch_size": args.batch_size,
        "seed": SEED,
        "prediction_file": str(prediction_path),
        "official_compatible_output": str(official_path),
        "official_output_sha256": _sha256_file(official_path),
        "scoring_note": (
            "Functional and security scores are intentionally absent until the official "
            "SALLM Docker tests and CodeQL workflow evaluate this output."
        ),
    }
    report_path = RESULTS_DIR / f"external_sallm_{tag}.json"
    _write_json(report_path, report)
    report_path.with_suffix(".md").write_text(
        "\n".join(
            (
                f"# External Evaluation: SALLM - {tag}",
                "",
                f"- Status: `{report['status']}`",
                f"- Records: {report['records']}",
                f"- Samples per prompt: {report['samples_per_prompt']}",
                f"- Compilable rate: {report['compilable_rate']:.4f}",
                f"- Benchmark revision: `{report['benchmark_revision']}`",
                f"- Dataset SHA-256: `{report['dataset_sha256']}`",
                "",
                report["scoring_note"],
                "",
            )
        ),
        encoding="utf-8",
    )
    return report


def _normalise_cwe(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("id") or value.get("cwe")
    match = re.search(r"(?:CWE[-_ ]?)?(\d+)", str(value or ""), re.IGNORECASE)
    return f"CWE-{int(match.group(1))}" if match else None


def _semgrep_result(
    path: str,
    line: int,
    cwe: str,
    rule_id: str,
    message: str,
    severity: str,
) -> dict[str, Any]:
    return {
        "check_id": f"pysecpatch.{rule_id}",
        "path": path.replace("\\", "/").lstrip("./"),
        "start": {"line": max(1, int(line)), "col": 1, "offset": 0},
        "end": {"line": max(1, int(line)), "col": 1, "offset": 0},
        "extra": {
            "message": message,
            "severity": severity.upper(),
            "metadata": {"cwe": [cwe], "confidence": "HIGH", "category": "security"},
        },
    }


def _scan_repo_for_realvuln(repo: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    python_files = list_python_files(repo)
    ast_findings, parse_errors = scan_ast(repo, python_files)
    bandit = run_bandit(repo)
    if bandit.get("count") is None:
        raise RuntimeError(f"Bandit failed for {repo.name}: {bandit.get('error') or 'unknown error'}")
    results: list[dict[str, Any]] = []
    for finding in ast_findings:
        cwe = AST_CHECK_CWE.get(finding["check"])
        if cwe:
            results.append(
                _semgrep_result(
                    finding["file"],
                    finding["line"],
                    cwe,
                    f"ast.{finding['check']}",
                    finding["message"],
                    finding["severity"],
                )
            )
    for finding in bandit.get("findings", []):
        cwe = _normalise_cwe(finding.get("issue_cwe"))
        if not cwe:
            continue
        filename = Path(str(finding.get("filename", "")))
        try:
            relative = filename.resolve().relative_to(repo.resolve()).as_posix()
        except (OSError, ValueError):
            relative = filename.as_posix().lstrip("./")
        results.append(
            _semgrep_result(
                relative,
                int(finding.get("line_number") or 1),
                cwe,
                f"bandit.{finding.get('test_id', 'unknown').lower()}",
                str(finding.get("issue_text") or "Bandit security finding."),
                str(finding.get("issue_severity") or "medium"),
            )
        )
    unique: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    for result in results:
        key = (
            result["path"],
            result["extra"]["metadata"]["cwe"][0],
            result["start"]["line"],
            result["check_id"],
        )
        unique[key] = result
    payload = {"version": "1.0.0", "results": list(unique.values())}
    metadata = {
        "python_files": len(python_files),
        "python_files_discovered": len(list(repo.rglob("*.py"))),
        "ast_findings": len(ast_findings),
        "bandit_findings": bandit.get("count"),
        "exported_findings": len(payload["results"]),
        "parse_errors": parse_errors,
        "bandit_error": bandit.get("error"),
        "bandit_warnings": bandit.get("warnings"),
        "bandit_excluded_paths": bandit.get("excluded_paths", []),
    }
    return payload, metadata


def _fbeta(precision: float, recall: float, beta: float) -> float:
    denominator = beta * beta * precision + recall
    return (1 + beta * beta) * precision * recall / denominator if denominator else 0.0


def realvuln_scan(args: argparse.Namespace) -> dict[str, Any]:
    audit_external_sources(None, args.realvuln_root)
    benchmark_revision = _git_commit(args.realvuln_root)
    if benchmark_revision != REALVULN_REVISION:
        raise RuntimeError(
            f"RealVuln revision mismatch: {benchmark_revision}; expected {REALVULN_REVISION}."
        )
    installed_bandit_version = bandit_version()
    if not installed_bandit_version:
        raise RuntimeError(
            "Bandit is required for RealVuln evaluation. Install it in the active Python "
            "environment with: python -m pip install bandit"
        )
    sys.path.insert(0, str(args.realvuln_root))
    from parsers.semgrep import SemgrepParser
    from scorer.matcher import load_ground_truth, match_findings
    from scorer.metrics import compute_scorecard

    gt_files = sorted((args.realvuln_root / "ground-truth").glob("*/ground-truth.json"))
    selected = set(args.repo or [])
    if selected:
        gt_files = [path for path in gt_files if path.parent.name in selected]
        missing = selected - {path.parent.name for path in gt_files}
        if missing:
            raise RuntimeError(f"Unknown RealVuln repos: {sorted(missing)}")
    if not gt_files:
        raise RuntimeError("No RealVuln ground-truth repositories selected.")
    target_revisions: dict[str, str] = {}
    target_sources: dict[str, str | None] = {}
    preflight_errors: list[str] = []
    for gt_file in gt_files:
        slug = gt_file.parent.name
        repo = args.realvuln_root / "repos" / slug
        ground_truth = json.loads(gt_file.read_text(encoding="utf-8"))
        expected_revision = str(ground_truth.get("commit_sha") or "").strip()
        if not repo.is_dir():
            preflight_errors.append(f"{slug}: repository is missing")
            continue
        actual_revision = _git_commit(repo)
        if not actual_revision:
            preflight_errors.append(f"{slug}: repository revision is unavailable")
            continue
        if expected_revision and actual_revision != expected_revision:
            preflight_errors.append(
                f"{slug}: revision {actual_revision} does not match {expected_revision}"
            )
            continue
        target_revisions[slug] = actual_revision
        target_sources[slug] = _git_remote_url(repo)
    if preflight_errors:
        details = "\n".join(f"- {error}" for error in preflight_errors)
        raise RuntimeError(f"RealVuln target preflight failed:\n{details}")
    families = json.loads((args.realvuln_root / "config" / "cwe-families.json").read_text())
    tag = _safe_tag(args.tag)
    per_repo: list[dict[str, Any]] = []
    raw_outputs: list[dict[str, Any]] = []
    totals = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for gt_file in gt_files:
        slug = gt_file.parent.name
        repo = args.realvuln_root / "repos" / slug
        gt = load_ground_truth(str(gt_file))
        if not repo.is_dir():
            vuln = sum(bool(item["is_vulnerable"]) for item in gt["findings"])
            traps = len(gt["findings"]) - vuln
            entry = {
                "repo": slug,
                "status": "missing_repo_strict_failure",
                "tp": 0,
                "fp": 0,
                "fn": vuln,
                "tn": traps,
            }
        else:
            payload, metadata = _scan_repo_for_realvuln(repo)
            output_dir = args.realvuln_root / "scan-results" / slug / tag
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / "run-1.json"
            _write_json(output_path, payload)
            raw_outputs.append({"repo": slug, "payload": payload})
            parser = SemgrepParser(scanner_slug=tag)
            findings = parser.parse(str(output_path))
            matches = match_findings(findings, gt)
            card = compute_scorecard(slug, tag, _utc_now(), matches, families)
            entry = {
                "repo": slug,
                "status": "complete",
                "target_revision": target_revisions[slug],
                "target_source": target_sources[slug],
                **card.to_dict(),
                "scan": metadata,
            }
        per_repo.append(entry)
        for key in totals:
            totals[key] += int(entry[key])
        print(f"[realvuln/{tag}] {len(per_repo)}/{len(gt_files)} {slug}", flush=True)
    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else 0.0
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else 0.0
    summary = {
        **totals,
        "precision": precision,
        "recall": recall,
        "f1": _fbeta(precision, recall, 1),
        "f2": _fbeta(precision, recall, 2),
        "f2_score": round(_fbeta(precision, recall, 2) * 100, 1),
        "f3": _fbeta(precision, recall, 3),
        "f3_score": round(_fbeta(precision, recall, 3) * 100, 1),
    }
    benchmark_manifest_path = args.realvuln_root / "benchmark-manifest.json"
    benchmark_manifest = json.loads(benchmark_manifest_path.read_text(encoding="utf-8"))
    raw_path = RESULTS_DIR / f"external_realvuln_{tag}.findings.jsonl"
    raw_path.write_text(
        "".join(json.dumps(item, ensure_ascii=True) + "\n" for item in raw_outputs),
        encoding="utf-8",
    )
    report = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "status": "complete",
        "benchmark": "RealVuln",
        "benchmark_revision": benchmark_revision,
        "benchmark_license": "MIT",
        "ground_truth_sha256": _sha256_json_tree(args.realvuln_root / "ground-truth"),
        "ground_truth_checkout_sha256": _sha256_tree(args.realvuln_root / "ground-truth"),
        "declared_ground_truth_content_hash": benchmark_manifest.get("ground_truth_content_hash"),
        "benchmark_manifest_sha256": _sha256_file(benchmark_manifest_path),
        "engine": "PySecPatch AST checks plus Bandit",
        "bandit_version": installed_bandit_version,
        "model_used": False,
        "scoring": "official file+CWE+line matching; strict micro over selected repositories",
        "selected_repositories": len(gt_files),
        "raw_findings_file": str(raw_path),
        "raw_findings_sha256": _sha256_file(raw_path),
        "summary": summary,
        "per_repository": per_repo,
    }
    report_path = RESULTS_DIR / f"external_realvuln_{tag}.json"
    _write_json(report_path, report)
    lines = [
        f"# External Evaluation: RealVuln - {tag}",
        "",
        f"- Repositories: {len(gt_files)}",
        f"- Engine: {report['engine']}",
        "- Model used: no",
        f"- Precision: {precision:.4f}",
        f"- Recall: {recall:.4f}",
        f"- F1: {summary['f1']:.4f}",
        f"- F2 score: {summary['f2_score']:.1f}",
        f"- F3 score: {summary['f3_score']:.1f}",
        "",
        "This evaluates the repository scanner front end, not LoRA repair generation.",
        "",
        "| Repository | Status | TP | FP | FN | TN |",
        "|---|---|---:|---:|---:|---:|",
    ]
    lines.extend(
        f"| {item['repo']} | {item['status']} | {item['tp']} | {item['fp']} | {item['fn']} | {item['tn']} |"
        for item in per_repo
    )
    report_path.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def self_test() -> dict[str, Any]:
    code, compilable, error = _extract_python("```python\nprint('ok')\n```", "")
    with tempfile.TemporaryDirectory() as temp:
        repo = Path(temp)
        (repo / "app.py").write_text("user = input()\neval(user)\n", encoding="utf-8")
        payload, metadata = _scan_repo_for_realvuln(repo)
    checks = {
        "fenced_python_extracted": code == "print('ok')",
        "extracted_python_parses": compilable and error is None,
        "dynamic_execution_exported": any(
            result["extra"]["metadata"]["cwe"] == ["CWE-94"] for result in payload["results"]
        ),
        "scanner_metadata_present": metadata["ast_findings"] >= 1,
        "f2_math": abs(_fbeta(1.0, 0.5, 2) - (5.0 / 9.0)) < 1e-12,
    }
    result = {"generated_at": _utc_now(), "status": "pass" if all(checks.values()) else "fail", "checks": checks}
    _write_json(RESULTS_DIR / "external_evaluator_self_test.json", result)
    if result["status"] != "pass":
        raise RuntimeError("External evaluator self-test failed.")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run licensed PySecPatch external benchmarks.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("self-test")

    audit = sub.add_parser("audit")
    audit.add_argument("--sallm-root", type=Path)
    audit.add_argument("--realvuln-root", type=Path)

    sallm = sub.add_parser("sallm-generate")
    sallm.add_argument("--sallm-root", type=Path, required=True)
    sallm.add_argument("--model", required=True)
    sallm.add_argument("--adapter", type=Path)
    sallm.add_argument("--tag", required=True)
    sallm.add_argument("--samples-per-prompt", type=int, default=1)
    sallm.add_argument("--temperature", type=float, default=0.0)
    sallm.add_argument("--batch-size", type=int, default=8)
    sallm.add_argument("--max-new-tokens", type=int, default=700)
    sallm.add_argument("--max-seq-len", type=int, default=4096)
    sallm.add_argument("--limit", type=int, default=0)
    sallm.add_argument("--force", action="store_true")

    realvuln = sub.add_parser("realvuln-scan")
    realvuln.add_argument("--realvuln-root", type=Path, required=True)
    realvuln.add_argument("--tag", default="pysecpatch-static-v1")
    realvuln.add_argument("--repo", action="append", help="official RealVuln repo slug")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    random.seed(SEED)
    try:
        if args.command == "self-test":
            result = self_test()
        elif args.command == "audit":
            if not args.sallm_root and not args.realvuln_root:
                raise RuntimeError("Audit requires at least one benchmark root.")
            result = audit_external_sources(args.sallm_root, args.realvuln_root)
        elif args.command == "sallm-generate":
            if (
                args.samples_per_prompt < 1
                or args.batch_size < 1
                or args.limit < 0
                or args.temperature < 0
            ):
                raise RuntimeError("Samples and batch size must be positive; limit and temperature cannot be negative.")
            result = sallm_generate(args)
        else:
            result = realvuln_scan(args)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        build_parser().exit(2, f"error: {exc}\n")
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
