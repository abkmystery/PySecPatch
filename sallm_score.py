"""Portable, evidence-first scoring for the pinned SALLM benchmark.

The functional path executes SALLM's unmodified per-prompt Dockerfiles and
tests. The CodeQL path is intentionally reported separately because the paper
repository does not pin its CodeQL CLI or query revision.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import math
import os
import random
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote


SCHEMA_VERSION = 1
SEED = 20260619
SALLM_REVISION = "0159a63daed0a88f461bbd69dd1160893e394a67"
SALLM_DATASET_SHA256S = {
    # Repository blob / clean checkout.
    "6ad17103bc2cea6327bd1d96dca2be783f1b6c6251ab8e0b1ac7a64d3fc3d2b1",
    # Raw representation recorded by the frozen RunPod generation audit.
    "6704778bb972b4bf73c4e664d8bd71e6e21e3046b8f63557854c71a87abb9c6c",
}
DEFAULT_INPUT_SHA256 = "9a11db1ad4a7eeef8ce4707ea47087206086732b3162512cba204bd67230dba3"
SALLM_MISSING_TEST_IDS = {
    "Assertion_Author_A_cwe215_0.py",
    "Assertion_Author_A_cwe306_0.py",
    "Assertion_Author_A_cwe319_0.py",
    "Assertion_Author_A_cwe798_0.py",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _append_jsonl(handle: Any, value: dict[str, Any]) -> None:
    handle.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")
    handle.flush()


def _git_revision(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _cwe_from_id(record_id: str) -> str:
    match = re.search(r"cwe(\d+)", record_id, flags=re.IGNORECASE)
    if not match:
        raise ValueError(f"SALLM record has no CWE identifier: {record_id}")
    return f"CWE-{int(match.group(1)):03d}"


def _source_filename(record_id: str) -> str:
    parts = record_id.split("_", 2)
    if len(parts) != 3 or not parts[2].endswith(".py"):
        raise ValueError(f"Unsupported SALLM record id: {record_id}")
    return parts[2]


def _load_and_validate(
    input_path: Path,
    sallm_root: Path | None,
    expected_input_sha256: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if expected_input_sha256 and _sha256(input_path) != expected_input_sha256:
        raise RuntimeError("Generated SALLM input hash does not match the frozen run.")
    records = _read_jsonl(input_path)
    if len(records) != 100:
        raise RuntimeError(f"Expected 100 SALLM prompts, found {len(records)}.")
    ids: set[str] = set()
    samples = 0
    for record in records:
        required = {"id", "technique", "source", "prompt", "output"}
        if not required.issubset(record):
            raise RuntimeError(f"Malformed SALLM record: {record.get('id', '<unknown>')}")
        if record["id"] in ids:
            raise RuntimeError(f"Duplicate SALLM record id: {record['id']}")
        ids.add(record["id"])
        if not isinstance(record["output"], list) or len(record["output"]) != 10:
            raise RuntimeError(f"Expected 10 outputs for {record['id']}.")
        for index, output in enumerate(record["output"]):
            if not isinstance(output, dict) or not isinstance(output.get("cleared_code"), str):
                raise RuntimeError(f"Missing cleared_code for {record['id']} sample {index}.")
            samples += 1

    dataset_sha = None
    revision = None
    if sallm_root:
        dataset_path = sallm_root / "Dataset" / "dataset.jsonl"
        if not dataset_path.is_file():
            raise RuntimeError("SALLM Dataset/dataset.jsonl is missing.")
        dataset_sha = _sha256(dataset_path)
        if dataset_sha not in SALLM_DATASET_SHA256S:
            raise RuntimeError(
                f"SALLM dataset hash mismatch: {dataset_sha}; expected a pinned representation."
            )
        revision = _git_revision(sallm_root)
        if revision != SALLM_REVISION:
            raise RuntimeError(f"SALLM revision mismatch: {revision}; expected {SALLM_REVISION}.")
        dataset_records = _read_jsonl(dataset_path)
        if len(dataset_records) != len(records):
            raise RuntimeError("Generated prompt count does not match the pinned SALLM dataset.")
        comparison_keys = ("id", "technique", "source", "prompt", "insecure_code")
        for generated, benchmark in zip(records, dataset_records):
            if any(generated.get(key) != benchmark.get(key) for key in comparison_keys):
                raise RuntimeError(
                    f"Generated prompt content differs from pinned SALLM record {benchmark.get('id')}."
                )

    return records, {
        "schema_version": SCHEMA_VERSION,
        "input_sha256": _sha256(input_path),
        "benchmark_revision": revision,
        "dataset_sha256": dataset_sha,
        "records": len(records),
        "samples": samples,
    }


def validate_command(args: argparse.Namespace) -> dict[str, Any]:
    _, metadata = _load_and_validate(args.input, args.sallm_root, args.expected_input_sha256)
    return {"generated_at": _utc_now(), "status": "pass", **metadata}


def _run(
    command: list[str],
    timeout: int,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        timeout=timeout,
        capture_output=True,
        text=True,
        errors="replace",
    )


def _test_results(path: Path) -> tuple[str | None, str | None]:
    correctness = None
    vulnerability = None
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            name = row.get("TestName", "").lower()
            result = row.get("Result")
            if "correctness" in name:
                correctness = result
            elif "vulnerability" in name:
                vulnerability = result
    return correctness, vulnerability


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-.")


def _failure_log(log_dir: Path, key: str, sections: Iterable[tuple[str, str]]) -> str:
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"{_safe_name(key)}.log"
    text = []
    for title, body in sections:
        if body:
            text.extend((f"## {title}", body[-50000:], ""))
    path.write_text("\n".join(text), encoding="utf-8")
    return str(path)


def _docker_preflight(docker: str) -> str:
    result = _run([docker, "version", "--format", "{{.Server.Version}}"], timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"Docker server is unavailable: {result.stderr.strip()}")
    return result.stdout.strip()


def functional_shard_command(args: argparse.Namespace) -> dict[str, Any]:
    records, metadata = _load_and_validate(
        args.input, args.sallm_root, args.expected_input_sha256
    )
    if args.shard_index < 0 or args.shard_index >= args.shard_count:
        raise ValueError("shard-index must be in [0, shard-count).")
    docker_version = _docker_preflight(args.docker)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    log_dir = args.output.with_suffix("").with_name(args.output.stem + "-failure-logs")

    existing = _read_jsonl(args.output) if args.output.is_file() else []
    completed = {(row["id"], int(row["sample_index"])) for row in existing}
    selected = [
        (prompt_index, record)
        for prompt_index, record in enumerate(records)
        if prompt_index % args.shard_count == args.shard_index
    ]
    total = sum(len(record["output"]) for _, record in selected)

    with args.output.open("a", encoding="utf-8", newline="\n") as handle:
        for prompt_index, record in selected:
            filename = _source_filename(record["id"])
            stem = Path(filename).stem
            context = args.sallm_root / "Dataset" / record["technique"] / record["source"]
            dockerfile = context / f"{stem}_Dockerfile"
            if not dockerfile.is_file():
                raise RuntimeError(f"Missing SALLM Dockerfile: {dockerfile}")

            for sample_index, output in enumerate(record["output"]):
                key = (record["id"], sample_index)
                if key in completed:
                    continue
                started = time.perf_counter()
                run_key = f"s{args.shard_index}-p{prompt_index}-r{sample_index}"
                image = f"pysecpatch-sallm-{run_key}"
                container = image
                csv_name = f"test_{stem}_results.csv"
                csv_path = args.output.parent / f".{run_key}-{csv_name}"
                script_content = base64.b64encode(
                    output["cleared_code"].encode("utf-8")
                ).decode("ascii")
                row: dict[str, Any] = {
                    "schema_version": SCHEMA_VERSION,
                    "benchmark": "SALLM",
                    "benchmark_revision": SALLM_REVISION,
                    "input_sha256": metadata["input_sha256"],
                    "id": record["id"],
                    "prompt_index": prompt_index,
                    "sample_index": sample_index,
                    "technique": record["technique"],
                    "source": record["source"],
                    "cwe": _cwe_from_id(record["id"]),
                    "compilable": bool(output.get("compilable")),
                    "status": "infrastructure_error",
                    "build_ok": False,
                    "run_ok": False,
                    "test_correctness": None,
                    "test_vulnerability": None,
                    "functional_pass": False,
                    "security_test_pass": False,
                    "secure_functional_pass": False,
                    "error": None,
                    "failure_log": None,
                }
                build = None
                run = None
                copy = None
                try:
                    _run([args.docker, "rm", "-f", container], timeout=30)
                    _run([args.docker, "image", "rm", "-f", image], timeout=30)
                    build = _run(
                        [
                            args.docker,
                            "build",
                            "--label",
                            "org.pysecpatch.benchmark=sallm",
                            "--build-arg",
                            f"SCRIPT_CONTENT={script_content}",
                            "-t",
                            image,
                            "-f",
                            str(dockerfile),
                            str(context),
                        ],
                        timeout=args.build_timeout,
                    )
                    row["build_ok"] = build.returncode == 0
                    if not row["build_ok"]:
                        row["error"] = f"docker build exited {build.returncode}"
                    else:
                        run = _run(
                            [
                                args.docker,
                                "run",
                                "--name",
                                container,
                                "--network",
                                "none",
                                "--cap-drop",
                                "ALL",
                                "--security-opt",
                                "no-new-privileges",
                                "--pids-limit",
                                "256",
                                "--memory",
                                args.memory,
                                "--cpus",
                                str(args.cpus),
                                image,
                            ],
                            timeout=args.run_timeout,
                        )
                        row["run_ok"] = run.returncode == 0
                        copy = _run(
                            [
                                args.docker,
                                "cp",
                                f"{container}:/prompt/{csv_name}",
                                str(csv_path),
                            ],
                            timeout=60,
                        )
                        if copy.returncode != 0 or not csv_path.is_file():
                            row["status"] = "complete"
                            row["test_correctness"] = (
                                "SyntaxError" if not row["compilable"] else "error"
                            )
                            row["test_vulnerability"] = row["test_correctness"]
                            row["error"] = "Model output failed before SALLM produced its result CSV."
                        else:
                            correctness, vulnerability = _test_results(csv_path)
                            row["test_correctness"] = correctness
                            row["test_vulnerability"] = vulnerability
                            row["functional_pass"] = correctness == "success"
                            row["security_test_pass"] = vulnerability == "success"
                            row["secure_functional_pass"] = bool(
                                row["functional_pass"] and row["security_test_pass"]
                            )
                            row["status"] = "complete"
                            if not row["run_ok"]:
                                row["error"] = f"docker run exited {run.returncode}"
                except subprocess.TimeoutExpired as exc:
                    row["error"] = f"timeout after {exc.timeout} seconds"
                except OSError as exc:
                    row["error"] = f"{type(exc).__name__}: {exc}"
                finally:
                    if row["status"] != "complete" or row["error"]:
                        sections = []
                        for title, result in (("build", build), ("run", run), ("copy", copy)):
                            if result is not None:
                                sections.append(
                                    (title, (result.stdout or "") + "\n" + (result.stderr or ""))
                                )
                        row["failure_log"] = _failure_log(log_dir, run_key, sections)
                    _run([args.docker, "rm", "-f", container], timeout=30)
                    _run([args.docker, "image", "rm", "-f", image], timeout=30)
                    csv_path.unlink(missing_ok=True)
                row["elapsed_seconds"] = round(time.perf_counter() - started, 6)
                _append_jsonl(handle, row)
                existing.append(row)
                print(
                    f"[sallm-functional/{args.shard_index}] {len(existing)}/{total} "
                    f"{record['id']} sample={sample_index} status={row['status']}",
                    flush=True,
                )

    return {
        "generated_at": _utc_now(),
        "status": "complete",
        "docker_server_version": docker_version,
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "expected_samples": total,
        "rows": len(existing),
        "output": str(args.output),
    }


def materialize_codeql_command(args: argparse.Namespace) -> dict[str, Any]:
    records, metadata = _load_and_validate(args.input, None, args.expected_input_sha256)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    mapping_path = args.output_dir / "source_map.jsonl"
    count = 0
    with mapping_path.open("w", encoding="utf-8", newline="\n") as mapping:
        for prompt_index, record in enumerate(records):
            filename = _source_filename(record["id"])
            prompt_dir = args.output_dir / f"p{prompt_index:03d}"
            prompt_dir.mkdir(parents=True, exist_ok=True)
            for sample_index, output in enumerate(record["output"]):
                relative = Path(f"p{prompt_index:03d}") / f"s{sample_index:02d}_{filename}"
                destination = args.output_dir / relative
                destination.write_text(output["cleared_code"], encoding="utf-8", newline="\n")
                _append_jsonl(
                    mapping,
                    {
                        "path": relative.as_posix(),
                        "id": record["id"],
                        "prompt_index": prompt_index,
                        "sample_index": sample_index,
                        "cwe": _cwe_from_id(record["id"]),
                        "compilable": bool(output.get("compilable")),
                    },
                )
                count += 1
    return {
        "generated_at": _utc_now(),
        "status": "complete",
        **metadata,
        "materialized_files": count,
        "source_map": str(mapping_path),
    }


def _sarif_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(root.rglob("*.sarif"))


def _rule_cwes(run: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    tool = run.get("tool", {})
    rules = list(tool.get("driver", {}).get("rules", []))
    for extension in tool.get("extensions", []):
        rules.extend(extension.get("rules", []))
    for rule in rules:
        tags = rule.get("properties", {}).get("tags", [])
        cwes = set()
        for tag in tags:
            match = re.search(r"cwe[-/](\d+)", str(tag), flags=re.IGNORECASE)
            if match:
                cwes.add(f"CWE-{int(match.group(1)):03d}")
        result[str(rule.get("id", ""))] = cwes
    return result


def codeql_summarize_command(args: argparse.Namespace) -> dict[str, Any]:
    mapping_rows = _read_jsonl(args.source_map)
    by_path = {row["path"].replace("\\", "/"): row for row in mapping_rows}
    counts = {
        path: {"findings": 0, "direct_findings": 0, "indirect_findings": 0, "rules": set()}
        for path in by_path
    }
    unmatched = 0
    sarif_paths = _sarif_files(args.sarif_dir)
    if not sarif_paths:
        raise RuntimeError(f"No SARIF files found under {args.sarif_dir}.")
    for sarif_path in sarif_paths:
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        for run in sarif.get("runs", []):
            rule_cwes = _rule_cwes(run)
            for finding in run.get("results", []):
                locations = finding.get("locations", [])
                uri = ""
                if locations:
                    uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get(
                        "uri", ""
                    )
                normalized = unquote(uri).replace("\\", "/").lstrip("./")
                matched_path = next(
                    (path for path in by_path if normalized == path or normalized.endswith("/" + path)),
                    None,
                )
                if not matched_path:
                    unmatched += 1
                    continue
                rule_id = str(finding.get("ruleId", "unknown"))
                item = counts[matched_path]
                item["findings"] += 1
                item["rules"].add(rule_id)
                if by_path[matched_path]["cwe"] in rule_cwes.get(rule_id, set()):
                    item["direct_findings"] += 1
                else:
                    item["indirect_findings"] += 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for path, source in by_path.items():
            item = counts[path]
            _append_jsonl(
                handle,
                {
                    **source,
                    "findings": item["findings"],
                    "direct_findings": item["direct_findings"],
                    "indirect_findings": item["indirect_findings"],
                    "finding_free": item["findings"] == 0,
                    "rules": sorted(item["rules"]),
                },
            )
    return {
        "generated_at": _utc_now(),
        "status": "complete",
        "sarif_files": len(sarif_paths),
        "source_files": len(mapping_rows),
        "unmatched_findings": unmatched,
        "output": str(args.output),
    }


def _estimate_pass_at_k(n: int, c: int, k: int) -> float:
    if n < k:
        raise ValueError(f"Cannot estimate pass@{k} from {n} samples.")
    if n - c < k:
        return 1.0
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)


def _mean(values: Iterable[float]) -> float:
    items = list(values)
    return sum(items) / len(items) if items else 0.0


def _bootstrap_ci(groups: list[list[dict[str, Any]]], key: str, samples: int) -> list[float]:
    rng = random.Random(SEED)
    estimates = []
    for _ in range(samples):
        chosen = [groups[rng.randrange(len(groups))] for _ in groups]
        values = [float(row[key]) for group in chosen for row in group]
        estimates.append(_mean(values))
    estimates.sort()
    low = estimates[int(0.025 * (samples - 1))]
    high = estimates[int(0.975 * (samples - 1))]
    return [low, high]


def aggregate_command(args: argparse.Namespace) -> dict[str, Any]:
    input_records, metadata = _load_and_validate(args.input, None, args.expected_input_sha256)
    shard_files = sorted(args.shards.rglob("shard-*.jsonl"))
    if not shard_files:
        raise RuntimeError(f"No functional shard files found under {args.shards}.")
    rows = [row for path in shard_files for row in _read_jsonl(path)]
    unique = {(row["id"], int(row["sample_index"])) for row in rows}
    expected = {
        (record["id"], sample_index)
        for record in input_records
        for sample_index in range(len(record["output"]))
    }
    if len(unique) != len(rows):
        raise RuntimeError("Functional shard outputs contain duplicate samples.")
    if unique != expected:
        missing = len(expected - unique)
        extra = len(unique - expected)
        raise RuntimeError(f"Functional shards are incomplete: missing={missing}, extra={extra}.")

    codeql_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    if args.codeql_summary:
        for row in _read_jsonl(args.codeql_summary):
            codeql_by_key[(row["id"], int(row["sample_index"]))] = row
        if set(codeql_by_key) != expected:
            raise RuntimeError("CodeQL summary does not cover the exact generated sample set.")

    rows.sort(key=lambda row: (int(row["prompt_index"]), int(row["sample_index"])))
    upstream_gap_keys: set[tuple[str, int]] = set()
    model_execution_errors = 0
    infrastructure_rows = []
    for row in rows:
        if row["status"] == "complete":
            if row.get("error") == "Model output failed before SALLM produced its result CSV.":
                model_execution_errors += 1
            continue
        key = (row["id"], int(row["sample_index"]))
        if row["id"] in SALLM_MISSING_TEST_IDS and str(row.get("error", "")).startswith(
            "docker build exited"
        ):
            upstream_gap_keys.add(key)
            row["status"] = "upstream_fixture_missing"
            continue
        if row.get("error") == "SALLM test result CSV was not produced.":
            row["status"] = "complete"
            row["test_correctness"] = "SyntaxError" if not row["compilable"] else "error"
            row["test_vulnerability"] = row["test_correctness"]
            row["functional_pass"] = False
            row["security_test_pass"] = False
            row["secure_functional_pass"] = False
            row["normalization_note"] = (
                "Model output failed before the upstream runner wrote CSV; counted as non-passing."
            )
            model_execution_errors += 1
            continue
        infrastructure_rows.append(row)

    combined = []
    for row in rows:
        key = (row["id"], int(row["sample_index"]))
        combined.append({**row, "codeql": codeql_by_key.get(key)})
    groups_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in combined:
        if (row["id"], int(row["sample_index"])) in upstream_gap_keys:
            continue
        groups_by_id[row["id"]].append(row)
    groups = [sorted(group, key=lambda row: int(row["sample_index"])) for group in groups_by_id.values()]
    scored_rows = [
        row
        for row in combined
        if (row["id"], int(row["sample_index"])) not in upstream_gap_keys
    ]

    metrics: dict[str, Any] = {
        "compilable_rate": _mean(float(row["compilable"]) for row in scored_rows),
        "functional_pass_rate": _mean(float(row["functional_pass"]) for row in scored_rows),
        "security_test_pass_rate": _mean(float(row["security_test_pass"]) for row in scored_rows),
        "secure_functional_pass_rate": _mean(
            float(row["secure_functional_pass"]) for row in scored_rows
        ),
    }
    metrics["cluster_bootstrap_95ci"] = {
        key: _bootstrap_ci(groups, key, args.bootstrap_samples)
        for key in ("functional_pass", "security_test_pass", "secure_functional_pass")
    }
    for key, label in (
        ("functional_pass", "pass_at_k"),
        ("secure_functional_pass", "secure_pass_at_k"),
    ):
        metrics[label] = {
            str(k): _mean(
                _estimate_pass_at_k(len(group), sum(bool(row[key]) for row in group), k)
                for group in groups
            )
            for k in (1, 3, 5)
        }
    metrics["vulnerable_at_k"] = {
        str(k): _mean(
            _estimate_pass_at_k(
                len(group), sum(row["test_vulnerability"] == "failure" for row in group), k
            )
            for group in groups
        )
        for k in (1, 3, 5)
    }
    if codeql_by_key:
        metrics["codeql"] = {
            "finding_free_rate": _mean(
                float(row["codeql"]["finding_free"]) for row in scored_rows
            ),
            "direct_finding_rate": _mean(
                float(row["codeql"]["direct_findings"] > 0) for row in scored_rows
            ),
            "any_finding_rate": _mean(
                float(row["codeql"]["findings"] > 0) for row in scored_rows
            ),
            "findings": sum(int(row["codeql"]["findings"]) for row in scored_rows),
        }

    scored_prompts = len(groups)
    upstream_gap_ids = sorted({record_id for record_id, _ in upstream_gap_keys})
    missing_prompts = len(upstream_gap_ids)
    metrics["full_benchmark_bounds"] = {
        metric: [
            sum(bool(row[metric]) for row in scored_rows) / len(combined),
            (sum(bool(row[metric]) for row in scored_rows) + len(upstream_gap_keys))
            / len(combined),
        ]
        for metric in (
            "functional_pass",
            "security_test_pass",
            "secure_functional_pass",
        )
    }
    for metric in ("pass_at_k", "secure_pass_at_k"):
        metrics["full_benchmark_bounds"][metric] = {
            str(k): [
                metrics[metric][str(k)] * scored_prompts / len(input_records),
                (metrics[metric][str(k)] * scored_prompts + missing_prompts)
                / len(input_records),
            ]
            for k in (1, 3, 5)
        }

    cwes: dict[str, Any] = {}
    for cwe in sorted({row["cwe"] for row in scored_rows}):
        subset = [row for row in scored_rows if row["cwe"] == cwe]
        cwes[cwe] = {
            "samples": len(subset),
            "functional_pass_rate": _mean(float(row["functional_pass"]) for row in subset),
            "security_test_pass_rate": _mean(float(row["security_test_pass"]) for row in subset),
            "secure_functional_pass_rate": _mean(
                float(row["secure_functional_pass"]) for row in subset
            ),
        }

    infrastructure_errors = len(infrastructure_rows)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "status": (
            "complete_with_upstream_limitations"
            if infrastructure_errors == 0
            else "failed_infrastructure_gate"
        ),
        "benchmark": "SALLM",
        "benchmark_revision": SALLM_REVISION,
        "input_sha256": metadata["input_sha256"],
        "records": len(groups),
        "samples": len(scored_rows),
        "total_records": len(input_records),
        "total_samples": len(combined),
        "upstream_fixture_missing_records": len(upstream_gap_ids),
        "upstream_fixture_missing_samples": len(upstream_gap_keys),
        "upstream_fixture_missing_ids": upstream_gap_ids,
        "model_execution_errors": model_execution_errors,
        "infrastructure_errors": infrastructure_errors,
        "bootstrap_samples": args.bootstrap_samples,
        "bootstrap_seed": SEED,
        "metrics": metrics,
        "by_cwe": cwes,
        "comparability": {
            "functional": (
                "Uses the pinned SALLM Dockerfiles and test cases. Added container resource and "
                "network isolation does not change benchmark assertions."
            ),
            "codeql": (
                "Uses the disclosed GitHub CodeQL security-extended suite bundled with the pinned "
                "CodeQL Action. It is reported separately because the SALLM paper repository does "
                "not pin the authors' CodeQL CLI or query revision."
            ),
        },
        "files": {
            "input": str(args.input),
            "functional_shards": [str(path) for path in shard_files],
            "codeql_summary": str(args.codeql_summary) if args.codeql_summary else None,
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    tag = _safe_name(args.tag)
    combined_path = args.output_dir / f"sallm_{tag}.combined.jsonl"
    with combined_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in combined:
            _append_jsonl(handle, row)
    report_path = args.output_dir / f"sallm_{tag}.json"
    _write_json(report_path, report)
    md_path = args.output_dir / f"sallm_{tag}.md"
    md_path.write_text(
        "\n".join(
            (
                f"# SALLM Evaluation: {args.tag}",
                "",
                f"- Status: `{report['status']}`",
                f"- Scored prompts: {report['records']} / {report['total_records']}",
                f"- Scored samples: {report['samples']} / {report['total_samples']}",
                f"- Upstream missing-fixture samples: {report['upstream_fixture_missing_samples']}",
                f"- Model execution errors: {report['model_execution_errors']}",
                f"- Infrastructure errors: {infrastructure_errors}",
                f"- Functional pass rate: {metrics['functional_pass_rate']:.4f}",
                f"- Security-test pass rate: {metrics['security_test_pass_rate']:.4f}",
                f"- Secure functional pass rate: {metrics['secure_functional_pass_rate']:.4f}",
                f"- Secure pass@1: {metrics['secure_pass_at_k']['1']:.4f}",
                f"- Secure pass@3: {metrics['secure_pass_at_k']['3']:.4f}",
                f"- Secure pass@5: {metrics['secure_pass_at_k']['5']:.4f}",
                "",
                "Functional results use the pinned SALLM Docker tests. CodeQL results use the "
                "separately disclosed security-extended query suite.",
                "",
            )
        ),
        encoding="utf-8",
    )
    evidence_paths = [report_path, md_path, combined_path, *shard_files]
    if args.codeql_summary:
        evidence_paths.append(args.codeql_summary)
    manifest_path = args.output_dir / f"sallm_{tag}.sha256"
    manifest_path.write_text(
        "".join(f"{_sha256(path)}  {path.as_posix()}\n" for path in evidence_paths),
        encoding="utf-8",
    )
    return report


def self_test_command(_: argparse.Namespace) -> dict[str, Any]:
    checks = {
        "pass_at_1": math.isclose(_estimate_pass_at_k(10, 3, 1), 0.3),
        "pass_at_5": math.isclose(_estimate_pass_at_k(10, 10, 5), 1.0),
        "cwe_parse": _cwe_from_id("Assertion_Author_A_cwe022_0.py") == "CWE-022",
        "filename_parse": _source_filename("Tainted_CodeQL_codeql_cwe089_0.py")
        == "codeql_cwe089_0.py",
        "safe_name": _safe_name("PySecPatch Test/SALLM") == "pysecpatch-test-sallm",
    }
    return {
        "generated_at": _utc_now(),
        "status": "pass" if all(checks.values()) else "fail",
        "checks": checks,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Portable scorer for pinned SALLM outputs.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("self-test")

    validate = sub.add_parser("validate")
    validate.add_argument("--input", type=Path, required=True)
    validate.add_argument("--sallm-root", type=Path, required=True)
    validate.add_argument("--expected-input-sha256", default=DEFAULT_INPUT_SHA256)

    functional = sub.add_parser("functional-shard")
    functional.add_argument("--input", type=Path, required=True)
    functional.add_argument("--sallm-root", type=Path, required=True)
    functional.add_argument("--output", type=Path, required=True)
    functional.add_argument("--shard-index", type=int, required=True)
    functional.add_argument("--shard-count", type=int, default=10)
    functional.add_argument("--expected-input-sha256", default=DEFAULT_INPUT_SHA256)
    functional.add_argument("--docker", default="docker")
    functional.add_argument("--build-timeout", type=int, default=900)
    functional.add_argument("--run-timeout", type=int, default=120)
    functional.add_argument("--memory", default="1g")
    functional.add_argument("--cpus", type=float, default=1.0)

    materialize = sub.add_parser("materialize-codeql")
    materialize.add_argument("--input", type=Path, required=True)
    materialize.add_argument("--output-dir", type=Path, required=True)
    materialize.add_argument("--expected-input-sha256", default=DEFAULT_INPUT_SHA256)

    codeql = sub.add_parser("codeql-summarize")
    codeql.add_argument("--source-map", type=Path, required=True)
    codeql.add_argument("--sarif-dir", type=Path, required=True)
    codeql.add_argument("--output", type=Path, required=True)

    aggregate = sub.add_parser("aggregate")
    aggregate.add_argument("--input", type=Path, required=True)
    aggregate.add_argument("--shards", type=Path, required=True)
    aggregate.add_argument("--codeql-summary", type=Path)
    aggregate.add_argument("--output-dir", type=Path, required=True)
    aggregate.add_argument("--tag", required=True)
    aggregate.add_argument("--expected-input-sha256", default=DEFAULT_INPUT_SHA256)
    aggregate.add_argument("--bootstrap-samples", type=int, default=2000)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        if args.command == "self-test":
            result = self_test_command(args)
        elif args.command == "validate":
            result = validate_command(args)
        elif args.command == "functional-shard":
            result = functional_shard_command(args)
        elif args.command == "materialize-codeql":
            result = materialize_codeql_command(args)
        elif args.command == "codeql-summarize":
            result = codeql_summarize_command(args)
        else:
            if args.bootstrap_samples < 100:
                raise ValueError("bootstrap-samples must be at least 100.")
            result = aggregate_command(args)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        build_parser().exit(2, f"error: {exc}\n")
    print(json.dumps(result, indent=2, ensure_ascii=True))
    if result.get("status") in {"fail", "failed_infrastructure_gate"}:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
