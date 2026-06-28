"""Frozen, paired repository-level repair evaluation for PySecPatch."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import random
import shutil
import subprocess
import sys
import tempfile
import time
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent import bandit_version, run_agent, run_bandit, scan_ast
from models import TransformersRepairModel


PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
RESULTS_DIR = PROJECT_DIR / "results"
DEFAULT_SUITE = DATA_DIR / "repo_benchmark.jsonl"
SEED = 20260619
SCHEMA_VERSION = 1
SKIP_HASH_PARTS = {".git", ".pytest_cache", "__pycache__", ".ruff_cache"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_tree(path: Path | None) -> str | None:
    if path is None or not path.is_dir():
        return None
    digest = hashlib.sha256()
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(item.read_bytes())
    return digest.hexdigest()


def _normalise_code(source: str) -> str:
    return "".join(source.split())


def _portable_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_DIR.resolve()).as_posix()
    except ValueError:
        return path.name


def _case(
    pair_id: str,
    family: str,
    framework: str,
    cwe: str,
    check: str,
    vulnerable_code: str,
    clean_code: str,
    test_code: str,
) -> list[dict[str, Any]]:
    common = {
        "pair_id": pair_id,
        "family": family,
        "framework": framework,
        "language": "python",
        "cwe": cwe,
        "expected_check": check,
        "target_file": "app.py",
        "protected_files": ["test_app.py", "notes.txt"],
        "source": "generated_after_model_freeze",
        "source_license": "Apache-2.0",
    }
    return [
        {
            **common,
            "id": f"{pair_id}-vulnerable",
            "is_vulnerable": True,
            "files": {
                "app.py": vulnerable_code.strip() + "\n",
                "test_app.py": test_code.strip() + "\n",
                "notes.txt": "This unrelated file must remain byte-for-byte unchanged.\n",
            },
        },
        {
            **common,
            "id": f"{pair_id}-clean",
            "is_vulnerable": False,
            "files": {
                "app.py": clean_code.strip() + "\n",
                "test_app.py": test_code.strip() + "\n",
                "notes.txt": "This unrelated file must remain byte-for-byte unchanged.\n",
            },
        },
    ]


def build_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    cases += _case(
        "repo6-command-flask",
        "repo6_command_subprocess",
        "flask-style",
        "CWE-078",
        "subprocess-shell-true",
        '''
import subprocess

def resolve_host(request):
    """Return the diagnostic process result for a requested host."""
    host = request.args.get("host", "localhost")
    return subprocess.run(f"nslookup {host}", shell=True, capture_output=True, text=True)
''',
        '''
import subprocess

def resolve_host(request):
    """Return the diagnostic process result for a requested host."""
    host = request.args.get("host", "localhost")
    return subprocess.run(["nslookup", host], shell=False, capture_output=True, text=True)
''',
        '''
import app

class Request:
    args = {"host": "example host"}

def test_command_uses_no_shell(monkeypatch):
    seen = {}
    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return object()
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    app.resolve_host(Request())
    assert isinstance(seen["command"], (list, tuple))
    assert seen["kwargs"].get("shell", False) is False
    assert "example host" in seen["command"]
''',
    )
    cases += _case(
        "repo6-command-cli",
        "repo6_command_os_system",
        "cli-style",
        "CWE-078",
        "os-system",
        '''
import os

def archive(folder):
    """Create an archive for one caller-provided folder."""
    return os.system(f"tar -czf backup.tgz {folder}")
''',
        '''
import subprocess

def archive(folder):
    """Create an archive for one caller-provided folder."""
    return subprocess.run(["tar", "-czf", "backup.tgz", folder], check=False).returncode
''',
        '''
import app

def test_archive_avoids_shell(monkeypatch):
    seen = {}
    if hasattr(app, "os"):
        monkeypatch.setattr(app.os, "system", lambda *_: (_ for _ in ()).throw(AssertionError("shell used")))
    class Result:
        returncode = 0
    if hasattr(app, "subprocess"):
        monkeypatch.setattr(app.subprocess, "run", lambda command, **kwargs: seen.update(command=command, kwargs=kwargs) or Result())
    assert app.archive("reports folder") == 0
    assert isinstance(seen["command"], (list, tuple))
    assert seen["kwargs"].get("shell", False) is False
''',
    )
    cases += _case(
        "repo6-eval-api",
        "repo6_dynamic_eval",
        "fastapi-style",
        "CWE-095",
        "dynamic-execution",
        '''
def decode_preferences(payload):
    """Decode a Python-literal preferences mapping supplied by an API client."""
    return eval(payload)
''',
        '''
import ast

def decode_preferences(payload):
    """Decode a Python-literal preferences mapping supplied by an API client."""
    return ast.literal_eval(payload)
''',
        '''
import pytest
import app

def test_literal_mapping_still_decodes():
    assert app.decode_preferences("{'theme': 'dark'}") == {"theme": "dark"}

def test_executable_expression_is_rejected():
    with pytest.raises(Exception):
        app.decode_preferences("sum([1, 2])")
''',
    )
    cases += _case(
        "repo6-eval-worker",
        "repo6_dynamic_builtins_eval",
        "worker-style",
        "CWE-095",
        "dynamic-execution",
        '''
import builtins

def parse_job_metadata(text):
    """Parse literal job metadata received from the queue."""
    return builtins.eval(text)
''',
        '''
import ast

def parse_job_metadata(text):
    """Parse literal job metadata received from the queue."""
    return ast.literal_eval(text)
''',
        '''
import pytest
import app

def test_literal_list_still_decodes():
    assert app.parse_job_metadata("['a', 2]") == ["a", 2]

def test_calls_are_rejected():
    with pytest.raises(Exception):
        app.parse_job_metadata("dict(value=1)")
''',
    )
    cases += _case(
        "repo6-yaml-service",
        "repo6_yaml_module_load",
        "service-style",
        "CWE-502",
        "unsafe-yaml-load",
        '''
import yaml

def load_settings(stream):
    """Load ordinary YAML configuration values."""
    return yaml.load(stream)
''',
        '''
import yaml

def load_settings(stream):
    """Load ordinary YAML configuration values."""
    return yaml.safe_load(stream)
''',
        '''
import pytest
import yaml
import app

def test_plain_yaml_loads():
    assert app.load_settings("enabled: true") == {"enabled": True}

def test_python_object_tag_is_rejected():
    with pytest.raises(yaml.YAMLError):
        app.load_settings("!!python/object/new:builtins.tuple [[1, 2]]")
''',
    )
    cases += _case(
        "repo6-yaml-job",
        "repo6_yaml_import_alias",
        "job-style",
        "CWE-502",
        "unsafe-yaml-load",
        '''
import yaml as config_yaml

def read_job(stream):
    """Read a plain YAML job description."""
    return config_yaml.load(stream, Loader=config_yaml.Loader)
''',
        '''
import yaml as config_yaml

def read_job(stream):
    """Read a plain YAML job description."""
    return config_yaml.safe_load(stream)
''',
        '''
import pytest
import yaml
import app

def test_job_mapping_loads():
    assert app.read_job("name: nightly") == {"name": "nightly"}

def test_unsafe_tag_is_rejected():
    with pytest.raises(yaml.YAMLError):
        app.read_job("!!python/object/new:builtins.tuple [[1, 2]]")
''',
    )
    cases += _case(
        "repo6-sql-flask",
        "repo6_sql_direct_fstring",
        "flask-style",
        "CWE-089",
        "sql-string-format",
        '''
def find_account(cursor, request):
    """Look up one account by its externally supplied name."""
    name = request.args.get("name", "")
    return cursor.execute(f"SELECT id FROM accounts WHERE name = '{name}'")
''',
        '''
def find_account(cursor, request):
    """Look up one account by its externally supplied name."""
    name = request.args.get("name", "")
    return cursor.execute("SELECT id FROM accounts WHERE name = ?", (name,))
''',
        '''
import app

class Request:
    args = {"name": "O'Reilly"}

class Cursor:
    def execute(self, *args):
        self.args = args
        return self

def test_query_is_parameterized():
    cursor = Cursor()
    app.find_account(cursor, Request())
    assert len(cursor.args) >= 2
    assert "O'Reilly" not in cursor.args[0]
    assert "O'Reilly" in cursor.args[1]
''',
    )
    cases += _case(
        "repo6-sql-django",
        "repo6_sql_assigned_format",
        "django-style",
        "CWE-089",
        "sql-string-format",
        '''
def search_orders(cursor, request):
    """Search orders using a request query parameter."""
    term = request.GET.get("q", "")
    return cursor.execute("SELECT id FROM orders WHERE note LIKE '%%%s%%'" % term)
'''.replace("request.GET.get", "request.args.get"),
        '''
def search_orders(cursor, request):
    """Search orders using a request query parameter."""
    term = request.args.get("q", "")
    query = "SELECT id FROM orders WHERE note LIKE ?"
    return cursor.execute(query, (f"%{term}%",))
''',
        '''
import app

class Request:
    args = {"q": "50%_archive"}

class Cursor:
    def execute(self, *args):
        self.args = args
        return self

def test_search_is_parameterized():
    cursor = Cursor()
    app.search_orders(cursor, Request())
    assert len(cursor.args) >= 2
    assert "50%_archive" not in cursor.args[0]
    assert any("50%_archive" in str(value) for value in cursor.args[1])
''',
    )
    cases += _case(
        "repo6-path-flask",
        "repo6_path_direct_open",
        "flask-style",
        "CWE-022",
        "path-traversal-open",
        '''
from pathlib import Path

DOCUMENT_ROOT = Path("documents")

def read_document(request):
    """Read one document beneath DOCUMENT_ROOT."""
    return open(request.args.get("name", "README.txt"), encoding="utf-8").read()
''',
        '''
from pathlib import Path

DOCUMENT_ROOT = Path("documents")

def read_document(request):
    """Read one document beneath DOCUMENT_ROOT."""
    root = DOCUMENT_ROOT.resolve()
    target = (root / request.args.get("name", "README.txt")).resolve()
    target.relative_to(root)
    return target.read_text(encoding="utf-8")
''',
        '''
import pytest
import app

class Request:
    def __init__(self, name):
        self.args = {"name": name}

def test_document_root_is_enforced(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "documents").mkdir()
    (tmp_path / "documents" / "ok.txt").write_text("ok", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("secret", encoding="utf-8")
    assert app.read_document(Request("ok.txt")) == "ok"
    with pytest.raises(Exception):
        app.read_document(Request("../secret.txt"))
''',
    )
    cases += _case(
        "repo6-path-api",
        "repo6_path_tainted_variable",
        "fastapi-style",
        "CWE-022",
        "path-traversal-open",
        '''
from pathlib import Path

EXPORT_ROOT = Path("exports")

def download_export(request):
    """Return one text export beneath EXPORT_ROOT."""
    filename = request.args.get("file", "latest.txt")
    return open(filename, encoding="utf-8").read()
''',
        '''
from pathlib import Path

EXPORT_ROOT = Path("exports")

def download_export(request):
    """Return one text export beneath EXPORT_ROOT."""
    root = EXPORT_ROOT.resolve()
    target = (root / request.args.get("file", "latest.txt")).resolve()
    target.relative_to(root)
    return target.read_text(encoding="utf-8")
''',
        '''
import pytest
import app

class Request:
    def __init__(self, name):
        self.args = {"file": name}

def test_export_root_is_enforced(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "latest.txt").write_text("report", encoding="utf-8")
    (tmp_path / "private.txt").write_text("private", encoding="utf-8")
    assert app.download_export(Request("latest.txt")) == "report"
    with pytest.raises(Exception):
        app.download_export(Request("../private.txt"))
''',
    )
    cases += _case(
        "repo6-secret-service",
        "repo6_secret_assignment",
        "service-style",
        "CWE-798",
        "hardcoded-secret",
        '''
API_KEY = "production-key-7f95d21c"

def get_api_key():
    """Return the service API key supplied by deployment configuration."""
    return API_KEY
''',
        '''
import os

def get_api_key():
    """Return the service API key supplied by deployment configuration."""
    return os.environ["API_KEY"]
''',
        '''
import ast
import importlib
import app

def test_key_comes_from_environment(monkeypatch):
    monkeypatch.setenv("API_KEY", "runtime-key")
    importlib.reload(app)
    assert app.get_api_key() == "runtime-key"
    tree = ast.parse(open(app.__file__, encoding="utf-8").read())
    forbidden = {"API_KEY", "SECRET", "PASSWORD"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            assert not any(isinstance(target, ast.Name) and target.id in forbidden for target in node.targets)
''',
    )
    cases += _case(
        "repo6-secret-worker",
        "repo6_secret_annotated",
        "worker-style",
        "CWE-798",
        "hardcoded-secret",
        '''
AUTH_TOKEN: str = "worker-token-3c815efa"

def worker_token():
    """Return the worker token supplied at runtime."""
    return AUTH_TOKEN
''',
        '''
import os

def worker_token():
    """Return the worker token supplied at runtime."""
    return os.environ["AUTH_TOKEN"]
''',
        '''
import ast
import importlib
import app

def test_token_comes_from_environment(monkeypatch):
    monkeypatch.setenv("AUTH_TOKEN", "runtime-token")
    importlib.reload(app)
    assert app.worker_token() == "runtime-token"
    tree = ast.parse(open(app.__file__, encoding="utf-8").read())
    assert not any(isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Constant) for node in ast.walk(tree))
''',
    )
    return cases


def _load_suite(path: Path) -> list[dict[str, Any]]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    required = {
        "id", "pair_id", "family", "framework", "language", "cwe", "expected_check",
        "is_vulnerable", "target_file", "protected_files", "source", "source_license", "files",
    }
    if not records or any(not required.issubset(record) for record in records):
        raise RuntimeError(f"Invalid repository benchmark schema: {path}")
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        raise RuntimeError("Repository benchmark contains duplicate IDs.")
    pairs: dict[str, list[bool]] = {}
    for record in records:
        if record["language"] != "python" or record["source_license"] != "Apache-2.0":
            raise RuntimeError(f"Unsupported language or license in {record['id']}.")
        pairs.setdefault(record["pair_id"], []).append(bool(record["is_vulnerable"]))
    if any(sorted(values) != [False, True] for values in pairs.values()):
        raise RuntimeError("Each pair must contain exactly one vulnerable and one clean fixture.")
    return records


def _training_hashes(training_data_dir: Path) -> tuple[set[str], set[str], list[dict[str, str]]]:
    hashes: set[str] = set()
    families: set[str] = set()
    checked: list[dict[str, str]] = []
    for name in ("train.jsonl", "val.jsonl", "test.jsonl", "holdout.jsonl"):
        path = training_data_dir / name
        if not path.is_file():
            continue
        checked.append({"name": name, "sha256": _sha256_file(path)})
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            families.add(str(record.get("family", "")))
            for field in ("vulnerable_code", "fixed_code"):
                source = record.get(field)
                if isinstance(source, str):
                    hashes.add(hashlib.sha256(_normalise_code(source).encode()).hexdigest())
    return hashes, families, checked


def build_suite(path: Path, training_data_dir: Path, force: bool) -> dict[str, Any]:
    if path.exists() and not force:
        raise RuntimeError(f"Suite already exists: {path}. Use --force only before freezing a new version.")
    records = build_cases()
    training_hashes, training_families, training_files = _training_hashes(training_data_dir)
    if len(training_files) != 4:
        raise RuntimeError(
            "Contamination checking requires train.jsonl, val.jsonl, test.jsonl, and holdout.jsonl; "
            "pass --training-data-dir with the preserved corpus."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    records = _load_suite(path)
    exact_matches = []
    family_overlap = []
    for record in records:
        source_hash = hashlib.sha256(
            _normalise_code(record["files"][record["target_file"]]).encode()
        ).hexdigest()
        if source_hash in training_hashes:
            exact_matches.append(record["id"])
        if record["family"] in training_families:
            family_overlap.append(record["family"])
    contamination = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "suite_sha256": _sha256_file(path),
        "training_files_checked": training_files,
        "normalised_exact_code_matches": sorted(exact_matches),
        "template_family_overlap": sorted(set(family_overlap)),
        "pass": not exact_matches and not family_overlap,
    }
    if not contamination["pass"]:
        path.unlink(missing_ok=True)
        raise RuntimeError("Stage 6 suite contamination check failed.")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _write_json(RESULTS_DIR / "stage6_contamination_report.json", contamination)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "status": "frozen",
        "suite": _portable_path(path),
        "suite_sha256": _sha256_file(path),
        "seed": SEED,
        "records": len(records),
        "pairs": len(records) // 2,
        "vulnerable": sum(bool(record["is_vulnerable"]) for record in records),
        "clean": sum(not bool(record["is_vulnerable"]) for record in records),
        "cwes": sorted({record["cwe"] for record in records}),
        "framework_styles": sorted({record["framework"] for record in records}),
        "source": "generated_after_model_freeze",
        "source_license": "Apache-2.0",
        "contamination_report": "results/stage6_contamination_report.json",
    }
    _write_json(RESULTS_DIR / "stage6_suite_manifest.json", manifest)
    return manifest


def _materialise(record: dict[str, Any], root: Path) -> None:
    for relative, content in record["files"].items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _prepare_dirty_git_repo(root: Path) -> list[str]:
    commands = (
        ["git", "init", "-q"],
        ["git", "config", "user.name", "PySecPatch Benchmark"],
        ["git", "config", "user.email", "benchmark@invalid.local"],
        ["git", "add", "--all"],
        ["git", "commit", "-q", "-m", "Frozen fixture baseline"],
    )
    for command in commands:
        completed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30, check=False)
        if completed.returncode != 0:
            raise RuntimeError(f"Fixture git setup failed: {completed.stderr.strip()}")
    note = root / "notes.txt"
    note.write_text(note.read_text(encoding="utf-8") + "Uncommitted user note.\n", encoding="utf-8")
    return _git_status(root)


def _git_status(root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"git status failed: {completed.stderr.strip()}")
    return completed.stdout.splitlines()


def _tree_hashes(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_HASH_PARTS for part in path.relative_to(root).parts):
            continue
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _run_pytest(root: Path) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return {
            "passed": completed.returncode == 0,
            "returncode": completed.returncode,
            "seconds": time.perf_counter() - started,
            "output": (completed.stdout + "\n" + completed.stderr).strip()[-4000:],
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "returncode": None, "seconds": time.perf_counter() - started, "output": "pytest timed out"}


def _changed_paths(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))


def _patch_lines(attempt: dict[str, Any] | None) -> int | None:
    if not attempt:
        return None
    raw = attempt.get("raw_output")
    if not isinstance(raw, str):
        return None
    try:
        patch = json.loads(raw).get("patch", "")
    except (json.JSONDecodeError, AttributeError):
        return None
    return sum(
        1 for line in patch.splitlines()
        if line[:1] in {"+", "-"} and not line.startswith(("+++", "---"))
    )


def _run_case(
    record: dict[str, Any],
    model: TransformersRepairModel,
    model_id: str,
    adapter: Path | None,
    max_new_tokens: int,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=f"pysecpatch-stage6-{record['id']}-") as name:
        repo = Path(name) / "repo"
        repo.mkdir()
        _materialise(record, repo)
        dirty_before = _prepare_dirty_git_repo(repo)
        baseline_tests = _run_pytest(repo)
        before = _tree_hashes(repo)
        bandit_before = run_bandit(repo)
        torch = model._torch
        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()
        args = Namespace(
            repo=str(repo), github=None, fix=True, model=model_id,
            adapter=str(adapter) if adapter else None, no_model=False,
            max_new_tokens=max_new_tokens,
        )
        started = time.perf_counter()
        report = run_agent(args, model_instance=model, write_reports=False)
        elapsed = time.perf_counter() - started
        peak_gpu_memory = torch.cuda.max_memory_allocated() if torch.cuda.is_available() else None
        after = _tree_hashes(repo)
        final_tests = _run_pytest(repo)
        bandit_after = run_bandit(repo)
        dirty_after = _git_status(repo)
        changed = _changed_paths(before, after)
        initial_match = next(
            (finding for finding in report["findings"] if finding["check"] == record["expected_check"]),
            None,
        )
        matching_attempts = [
            item for item in report["repair_attempts"]
            if initial_match and item["finding_id"] == initial_match["id"]
        ]
        attempt = matching_attempts[-1] if matching_attempts else None
        final_match = any(
            finding["check"] == record["expected_check"]
            for finding in scan_ast(repo)[0]
        )
        protected_unchanged = all(path not in changed for path in record["protected_files"])
        expected_changes = [record["target_file"]] if attempt and attempt.get("accepted") else []
        unrelated_rewrites = [path for path in changed if path != record["target_file"]]
        repair_success = bool(
            record["is_vulnerable"]
            and initial_match
            and attempt
            and attempt.get("accepted")
            and not final_match
            and final_tests["passed"]
            and changed == [record["target_file"]]
            and protected_unchanged
        )
        clean_preserved = bool(
            not record["is_vulnerable"]
            and initial_match is None
            and not report["findings"]
            and not changed
            and final_tests["passed"]
            and protected_unchanged
        )
        return {
            "id": record["id"],
            "pair_id": record["pair_id"],
            "family": record["family"],
            "framework": record["framework"],
            "cwe": record["cwe"],
            "expected_check": record["expected_check"],
            "is_vulnerable": record["is_vulnerable"],
            "baseline_tests": baseline_tests,
            "final_tests": final_tests,
            "expected_finding_detected": initial_match is not None,
            "initial_finding_count": len(report["findings"]),
            "invalid_json": bool(attempt and attempt.get("invalid_json")),
            "patch_accepted": bool(attempt and attempt.get("accepted")),
            "expected_finding_removed": bool(initial_match and not final_match),
            "repair_success": repair_success,
            "clean_preserved": clean_preserved,
            "changed_paths": changed,
            "expected_changed_paths": expected_changes,
            "unrelated_file_rewrites": unrelated_rewrites,
            "protected_files_unchanged": protected_unchanged,
            "dirty_status_before": dirty_before,
            "dirty_status_after": dirty_after,
            "preexisting_dirty_change_preserved": " M notes.txt" in dirty_after and protected_unchanged,
            "patch_changed_lines": _patch_lines(attempt),
            "bandit_before": bandit_before.get("count"),
            "bandit_after": bandit_after.get("count"),
            "bandit_delta": (
                bandit_after["count"] - bandit_before["count"]
                if bandit_before.get("count") is not None and bandit_after.get("count") is not None
                else None
            ),
            "runtime_seconds": elapsed,
            "peak_gpu_memory_bytes": peak_gpu_memory,
            "attempt": attempt,
            "agent_summary": report["summary"],
            "model_error": report["verification"]["model_error"],
        }


def run_suite(args: argparse.Namespace) -> dict[str, Any]:
    if importlib.util.find_spec("pytest") is None:
        raise RuntimeError("pytest is required for Stage 6; install requirements.txt in the active environment.")
    records = _load_suite(args.suite)
    suite_sha = _sha256_file(args.suite)
    if args.expected_suite_sha256 and suite_sha != args.expected_suite_sha256.lower():
        raise RuntimeError(f"Suite SHA-256 mismatch: {suite_sha}")
    version = bandit_version()
    if version is None:
        raise RuntimeError("Bandit is required for Stage 6 evaluation.")
    adapter = args.adapter.resolve() if args.adapter else None
    if adapter is not None and not adapter.is_dir():
        raise RuntimeError(f"Adapter directory does not exist: {adapter}")
    tag = args.tag.replace("/", "-").replace("\\", "-")
    predictions = RESULTS_DIR / f"stage6_{tag}.predictions.jsonl"
    manifest_path = RESULTS_DIR / f"stage6_{tag}.run.json"
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "benchmark": "PySecPatch Stage 6 repository repair",
        "suite_sha256": suite_sha,
        "records": len(records),
        "model": args.model,
        "adapter": str(adapter) if adapter else None,
        "adapter_sha256": _sha256_tree(adapter),
        "max_new_tokens": args.max_new_tokens,
        "seed": SEED,
        "bandit_version": version,
    }
    if manifest_path.exists():
        if json.loads(manifest_path.read_text(encoding="utf-8")) != manifest:
            raise RuntimeError("Existing tag has different frozen settings; choose a new tag.")
    else:
        _write_json(manifest_path, manifest)
    existing: list[dict[str, Any]] = []
    if predictions.exists():
        existing = [json.loads(line) for line in predictions.read_text(encoding="utf-8").splitlines() if line.strip()]
    completed = {row["id"] for row in existing}
    pending = [record for record in records if record["id"] not in completed]
    if not pending:
        return summarize_predictions(predictions, tag)
    model = TransformersRepairModel(args.model, str(adapter) if adapter else None, args.max_seq_len)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with predictions.open("a", encoding="utf-8", newline="\n") as handle:
        for index, record in enumerate(pending, start=1):
            row = _run_case(record, model, args.model, adapter, args.max_new_tokens)
            handle.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")
            handle.flush()
            existing.append(row)
            print(f"[stage6/{tag}] {len(existing)}/{len(records)} {record['id']}", flush=True)
    return summarize_predictions(predictions, tag)


def _wilson(successes: int, total: int) -> list[float]:
    if total == 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    radius = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [max(0.0, centre - radius), min(1.0, centre + radius)]


def summarize_predictions(path: Path, tag: str | None = None) -> dict[str, Any]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    vulnerable = [row for row in rows if row["is_vulnerable"]]
    clean = [row for row in rows if not row["is_vulnerable"]]
    detected = sum(row["expected_finding_detected"] for row in vulnerable)
    clean_false_positives = sum(bool(row["initial_finding_count"]) for row in clean)
    detection_tp = detected
    detection_fn = len(vulnerable) - detected
    detection_fp = clean_false_positives
    detection_tn = len(clean) - clean_false_positives
    detection_precision = detection_tp / (detection_tp + detection_fp) if detection_tp + detection_fp else 0.0
    detection_recall = detection_tp / len(vulnerable) if vulnerable else 0.0
    repaired = sum(row["repair_success"] for row in vulnerable)
    preserved = sum(row["clean_preserved"] for row in clean)
    accepted = sum(row["patch_accepted"] for row in vulnerable)
    valid_json = sum(not row["invalid_json"] for row in vulnerable)
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "status": "complete",
        "tag": tag or path.stem.removeprefix("stage6_").removesuffix(".predictions"),
        "records": len(rows),
        "vulnerable_records": len(vulnerable),
        "clean_records": len(clean),
        "metrics": {
            "detection_confusion": {
                "tp": detection_tp, "fp": detection_fp, "fn": detection_fn, "tn": detection_tn,
            },
            "detection_precision": detection_precision,
            "detection_recall": detection_recall,
            "detection_f1": (
                2 * detection_precision * detection_recall / (detection_precision + detection_recall)
                if detection_precision + detection_recall else 0.0
            ),
            "detection_false_positive_rate": detection_fp / len(clean) if clean else 0.0,
            "detection_recall_ci95": _wilson(detected, len(vulnerable)),
            "strict_json_rate": valid_json / len(vulnerable) if vulnerable else 0.0,
            "patch_acceptance_rate": accepted / len(vulnerable) if vulnerable else 0.0,
            "end_to_end_repair_rate": repaired / len(vulnerable) if vulnerable else 0.0,
            "end_to_end_repair_ci95": _wilson(repaired, len(vulnerable)),
            "clean_preservation_rate": preserved / len(clean) if clean else 0.0,
            "clean_preservation_ci95": _wilson(preserved, len(clean)),
            "unrelated_file_rewrites": sum(len(row["unrelated_file_rewrites"]) for row in rows),
            "bandit_regressions": sum((row["bandit_delta"] or 0) > 0 for row in rows),
            "median_patch_changed_lines": (
                sorted(row["patch_changed_lines"] for row in vulnerable if row["patch_changed_lines"] is not None)[
                    len([row for row in vulnerable if row["patch_changed_lines"] is not None]) // 2
                ]
                if any(row["patch_changed_lines"] is not None for row in vulnerable) else None
            ),
            "total_runtime_seconds": sum(row["runtime_seconds"] for row in rows),
            "peak_gpu_memory_bytes": max(
                (row["peak_gpu_memory_bytes"] for row in rows if row["peak_gpu_memory_bytes"] is not None),
                default=None,
            ),
        },
        "predictions_file": str(path),
        "predictions_sha256": _sha256_file(path),
    }
    output = RESULTS_DIR / f"stage6_{result['tag']}.json"
    _write_json(output, result)
    markdown = [
        f"# Stage 6 Repository Repair: {result['tag']}", "",
        f"- Records: {len(rows)} ({len(vulnerable)} vulnerable, {len(clean)} clean)",
        f"- Detection recall: {result['metrics']['detection_recall']:.4f}",
        f"- Detection precision: {result['metrics']['detection_precision']:.4f}",
        f"- Strict JSON rate: {result['metrics']['strict_json_rate']:.4f}",
        f"- Patch acceptance rate: {result['metrics']['patch_acceptance_rate']:.4f}",
        f"- End-to-end repair rate: {result['metrics']['end_to_end_repair_rate']:.4f}",
        f"- Clean preservation rate: {result['metrics']['clean_preservation_rate']:.4f}",
        f"- Unrelated file rewrites: {result['metrics']['unrelated_file_rewrites']}",
        f"- Bandit regressions: {result['metrics']['bandit_regressions']}", "",
        "This controlled benchmark is paired across the frozen base and adapter. It is not an external benchmark.",
    ]
    output.with_suffix(".md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    return result


def _exact_mcnemar(adapter_only: int, base_only: int) -> float:
    discordant = adapter_only + base_only
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, index) for index in range(0, min(adapter_only, base_only) + 1))
    return min(1.0, 2 * tail / (2 ** discordant))


def compare_runs(base_path: Path, adapter_path: Path, tag: str, bootstrap_samples: int) -> dict[str, Any]:
    base = {row["id"]: row for row in _read_predictions(base_path)}
    adapter = {row["id"]: row for row in _read_predictions(adapter_path)}
    if set(base) != set(adapter):
        raise RuntimeError("Base and adapter prediction IDs differ.")
    ids = sorted(record_id for record_id in base if base[record_id]["is_vulnerable"])
    base_values = [int(base[record_id]["repair_success"]) for record_id in ids]
    adapter_values = [int(adapter[record_id]["repair_success"]) for record_id in ids]
    adapter_only = sum(a == 1 and b == 0 for a, b in zip(adapter_values, base_values))
    base_only = sum(a == 0 and b == 1 for a, b in zip(adapter_values, base_values))
    rng = random.Random(SEED)
    effects = []
    for _ in range(bootstrap_samples):
        sample = [rng.randrange(len(ids)) for _ in ids]
        effects.append(sum(adapter_values[i] - base_values[i] for i in sample) / len(ids))
    effects.sort()
    low = effects[int(0.025 * (len(effects) - 1))]
    high = effects[int(0.975 * (len(effects) - 1))]
    effect = sum(adapter_values) / len(ids) - sum(base_values) / len(ids)
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "status": "complete",
        "tag": tag,
        "paired_vulnerable_cases": len(ids),
        "base_end_to_end_repair_rate": sum(base_values) / len(ids),
        "adapter_end_to_end_repair_rate": sum(adapter_values) / len(ids),
        "paired_absolute_effect": effect,
        "paired_bootstrap_ci95": [low, high],
        "adapter_only_successes": adapter_only,
        "base_only_successes": base_only,
        "mcnemar_exact_p": _exact_mcnemar(adapter_only, base_only),
        "bootstrap_samples": bootstrap_samples,
        "seed": SEED,
        "base_predictions_sha256": _sha256_file(base_path),
        "adapter_predictions_sha256": _sha256_file(adapter_path),
    }
    output = RESULTS_DIR / f"stage6_comparison_{tag}.json"
    _write_json(output, result)
    output.with_suffix(".md").write_text(
        "\n".join(
            (
                f"# Stage 6 Paired Comparison: {tag}", "",
                f"- Paired vulnerable cases: {len(ids)}",
                f"- Base end-to-end repair rate: {result['base_end_to_end_repair_rate']:.4f}",
                f"- Adapter end-to-end repair rate: {result['adapter_end_to_end_repair_rate']:.4f}",
                f"- Absolute paired effect: {effect:+.4f}",
                f"- 95% paired bootstrap CI: [{low:+.4f}, {high:+.4f}]",
                f"- Exact McNemar p-value: {result['mcnemar_exact_p']:.6f}", "",
                "Statistical significance is not claimed when the interval includes zero or the corrected p-value exceeds the pre-registered threshold.",
            )
        ) + "\n",
        encoding="utf-8",
    )
    return result


def _read_predictions(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def self_test() -> dict[str, Any]:
    cases = build_cases()
    with tempfile.TemporaryDirectory(prefix="pysecpatch-stage6-self-test-") as name:
        root = Path(name)
        _materialise(cases[0], root)
        dirty_status = _prepare_dirty_git_repo(root)
    checks = {
        "records_are_paired": len(cases) == 24 and sum(record["is_vulnerable"] for record in cases) == 12,
        "ids_are_unique": len({record["id"] for record in cases}) == len(cases),
        "only_python_targets": all(record["target_file"].endswith(".py") for record in cases),
        "licenses_are_known": all(record["source_license"] == "Apache-2.0" for record in cases),
        "protected_files_present": all(
            all(path in record["files"] for path in record["protected_files"]) for record in cases
        ),
        "dirty_worktree_prepared": dirty_status == [" M notes.txt"],
    }
    result = {"generated_at": _utc_now(), "status": "pass" if all(checks.values()) else "fail", "checks": checks}
    _write_json(RESULTS_DIR / "stage6_self_test.json", result)
    if result["status"] != "pass":
        raise RuntimeError("Stage 6 self-test failed.")
    return result


def validate_suite(path: Path, expected_sha256: str | None) -> dict[str, Any]:
    if importlib.util.find_spec("pytest") is None:
        raise RuntimeError("pytest is required to validate Stage 6 fixtures; install requirements.txt first.")
    records = _load_suite(path)
    suite_sha = _sha256_file(path)
    if expected_sha256 and suite_sha != expected_sha256.lower():
        raise RuntimeError(f"Suite SHA-256 mismatch: {suite_sha}")
    rows = []
    for record in records:
        with tempfile.TemporaryDirectory(prefix="pysecpatch-stage6-validate-") as name:
            repo = Path(name)
            _materialise(record, repo)
            findings = scan_ast(repo)[0]
            tests = _run_pytest(repo)
            expected = any(finding["check"] == record["expected_check"] for finding in findings)
            passed = bool(
                (record["is_vulnerable"] and expected and not tests["passed"])
                or (not record["is_vulnerable"] and not findings and tests["passed"])
            )
            rows.append(
                {
                    "id": record["id"],
                    "is_vulnerable": record["is_vulnerable"],
                    "expected_finding_detected": expected,
                    "finding_checks": sorted(finding["check"] for finding in findings),
                    "baseline_tests_passed": tests["passed"],
                    "passed": passed,
                    "test_output": tests["output"] if not passed else None,
                }
            )
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "status": "pass" if all(row["passed"] for row in rows) else "fail",
        "suite_sha256": suite_sha,
        "records": len(rows),
        "passed": sum(row["passed"] for row in rows),
        "failed": sum(not row["passed"] for row in rows),
        "cases": rows,
    }
    _write_json(RESULTS_DIR / "stage6_suite_validation.json", result)
    if result["status"] != "pass":
        failed = ", ".join(row["id"] for row in rows if not row["passed"])
        raise RuntimeError(f"Stage 6 suite validation failed: {failed}")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("self-test")
    validate = sub.add_parser("validate-suite")
    validate.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    validate.add_argument("--expected-suite-sha256")
    build = sub.add_parser("build")
    build.add_argument("--output", type=Path, default=DEFAULT_SUITE)
    build.add_argument("--training-data-dir", type=Path, default=DATA_DIR)
    build.add_argument("--force", action="store_true")
    run = sub.add_parser("run")
    run.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    run.add_argument("--expected-suite-sha256")
    run.add_argument("--model", required=True)
    run.add_argument("--adapter", type=Path)
    run.add_argument("--tag", required=True)
    run.add_argument("--max-seq-len", type=int, default=4096)
    run.add_argument("--max-new-tokens", type=int, default=900)
    summarize = sub.add_parser("summarize")
    summarize.add_argument("--predictions", type=Path, required=True)
    summarize.add_argument("--tag")
    compare = sub.add_parser("compare")
    compare.add_argument("--base", type=Path, required=True)
    compare.add_argument("--adapter", type=Path, required=True)
    compare.add_argument("--tag", required=True)
    compare.add_argument("--bootstrap-samples", type=int, default=10000)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "self-test":
            result = self_test()
        elif args.command == "validate-suite":
            result = validate_suite(args.suite, args.expected_suite_sha256)
        elif args.command == "build":
            result = build_suite(args.output, args.training_data_dir, args.force)
        elif args.command == "run":
            result = run_suite(args)
        elif args.command == "summarize":
            result = summarize_predictions(args.predictions, args.tag)
        else:
            result = compare_runs(args.base, args.adapter, args.tag, args.bootstrap_samples)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        build_parser().exit(2, f"error: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
