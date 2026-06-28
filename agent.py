"""Defensive Python repository scanner and minimal repair agent."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from models import TransformersRepairModel
from report import write_agent_markdown


PROJECT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = PROJECT_DIR / "results"
JSON_REPORT = RESULTS_DIR / "agent_report.json"
MARKDOWN_REPORT = RESULTS_DIR / "agent_report.md"
CONFIG_PATH = PROJECT_DIR / "config.yaml"
SKIP_DIRS = {".git", ".hg", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".venv", "venv", "__pycache__"}
GITHUB_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$")
SECRET_NAME_RE = re.compile(
    r"(?:password|passwd|pwd|secret|api_?key|access_?key|auth_?token|private_?key)$",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(r"^(?:changeme|example|placeholder|your[_ -].*|xxx+|test|dummy)$", re.IGNORECASE)
SQL_WORD_RE = re.compile(r"\b(?:select|insert|update|delete|replace)\b", re.IGNORECASE)
ADDED_BANNED_PATTERNS = (
    re.compile(r"\b(?:eval|exec)\s*\("),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bpickle\.loads?\s*\("),
    re.compile(r"\bshell\s*=\s*True\b"),
    re.compile(r"\byaml\.load\s*\("),
)


def _qualified_name(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
        return {node.slice.value}
    if isinstance(node, (ast.Tuple, ast.List)):
        return set().union(*(_target_names(item) for item in node.elts)) if node.elts else set()
    return set()


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, relative_path: str, source: str) -> None:
        self.relative_path = relative_path
        self.source = source
        self.findings: list[dict[str, Any]] = []
        self.tainted_names: set[str] = set()
        self.unsafe_sql_names: set[str] = set()
        self.subprocess_modules = {"subprocess"}
        self.subprocess_calls: set[str] = set()
        self.os_modules = {"os"}
        self.os_system_calls: set[str] = set()
        self.yaml_modules = {"yaml"}
        self.yaml_load_calls: set[str] = set()
        self.pickle_modules = {"pickle", "cPickle"}
        self.pickle_load_calls: set[str] = set()

    def add(self, node: ast.AST, check: str, severity: str, message: str) -> None:
        self.findings.append(
            {
                "check": check,
                "severity": severity,
                "file": self.relative_path,
                "line": getattr(node, "lineno", 1),
                "column": getattr(node, "col_offset", 0),
                "message": message,
            }
        )

    def is_tainted(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted_names:
                return True
            if isinstance(child, ast.Call) and _qualified_name(child.func) == "input":
                return True
            name = _qualified_name(child)
            if name.startswith(("request.args", "request.form", "request.json", "request.values")):
                return True
            if name.startswith(("sys.argv", "os.environ")):
                return True
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.is_tainted(node.value):
            for target in node.targets:
                self.tainted_names.update(_target_names(target))
        if self._is_formatted_sql(node.value) and self.is_tainted(node.value):
            for target in node.targets:
                self.unsafe_sql_names.update(_target_names(target))
        self._check_secret(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            if self.is_tainted(node.value):
                self.tainted_names.update(_target_names(node.target))
            if self._is_formatted_sql(node.value) and self.is_tainted(node.value):
                self.unsafe_sql_names.update(_target_names(node.target))
            self._check_secret([node.target], node.value, node)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name
            if alias.name == "subprocess":
                self.subprocess_modules.add(local_name)
            elif alias.name == "os":
                self.os_modules.add(local_name)
            elif alias.name == "yaml":
                self.yaml_modules.add(local_name)
            elif alias.name in {"pickle", "cPickle"}:
                self.pickle_modules.add(local_name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name
            if node.module == "subprocess":
                self.subprocess_calls.add(local_name)
            elif node.module == "os" and alias.name == "system":
                self.os_system_calls.add(local_name)
            elif node.module == "yaml" and alias.name == "load":
                self.yaml_load_calls.add(local_name)
            elif node.module in {"pickle", "cPickle"} and alias.name in {"load", "loads"}:
                self.pickle_load_calls.add(local_name)

    def _is_formatted_sql(self, node: ast.AST) -> bool:
        source = ast.get_source_segment(self.source, node) or ""
        formatted = isinstance(node, ast.JoinedStr) or (
            isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
        ) or (isinstance(node, ast.Call) and _qualified_name(node.func).endswith(".format"))
        return formatted and bool(SQL_WORD_RE.search(source))

    def _check_secret(self, targets: list[ast.AST], value: ast.AST, node: ast.AST) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        literal = value.value.strip()
        if len(literal) < 8 or PLACEHOLDER_RE.match(literal):
            return
        for target in targets:
            for name in _target_names(target):
                if SECRET_NAME_RE.search(name):
                    self.add(node, "hardcoded-secret", "HIGH", f"Secret-like value assigned to {name!r}.")

    def visit_Call(self, node: ast.Call) -> None:
        name = _qualified_name(node.func)
        root = name.split(".", 1)[0]
        if root in self.subprocess_modules or name in self.subprocess_calls:
            shell_kw = next((kw for kw in node.keywords if kw.arg == "shell"), None)
            if shell_kw and isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True:
                self.add(node, "subprocess-shell-true", "HIGH", "subprocess call uses shell=True.")
        if (root in self.os_modules and name.endswith(".system")) or name in self.os_system_calls:
            self.add(node, "os-system", "HIGH", "os.system executes through a command shell.")
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self.add(node, "dynamic-execution", "HIGH", f"{name} executes dynamic Python code.")
        if (root in self.yaml_modules and name.endswith(".load")) or name in self.yaml_load_calls:
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
            loader_name = _qualified_name(loader) if loader is not None else ""
            if loader_name not in {"SafeLoader", "CSafeLoader", "yaml.SafeLoader", "yaml.CSafeLoader"}:
                self.add(node, "unsafe-yaml-load", "HIGH", "yaml.load is used without a SafeLoader.")
        if (
            root in self.pickle_modules and name.rsplit(".", 1)[-1] in {"load", "loads"}
        ) or name in self.pickle_load_calls:
            self.add(node, "unsafe-pickle-load", "HIGH", "pickle deserialization can execute attacker-controlled code.")
        if name.rsplit(".", 1)[-1] in {"execute", "executemany"} and node.args:
            query = node.args[0]
            unsafe_name = isinstance(query, ast.Name) and query.id in self.unsafe_sql_names
            if (self._is_formatted_sql(query) and self.is_tainted(query)) or unsafe_name:
                self.add(node, "sql-string-format", "HIGH", "SQL query formats suspicious external input.")
        if name in {"open", "io.open"} and node.args and self.is_tainted(node.args[0]):
            self.add(node, "path-traversal-open", "MEDIUM", "open() receives a path derived from unsanitized input.")
        elif name.endswith(".open") and self.is_tainted(node.func):
            self.add(node, "path-traversal-open", "MEDIUM", "Path.open() is derived from unsanitized input.")
        self.generic_visit(node)


def list_python_files(repo: Path) -> list[Path]:
    files: list[Path] = []
    for path in repo.rglob("*.py"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(repo).parts):
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(repo).as_posix())


def scan_ast(repo: Path, files: list[Path] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []
    for path in files or list_python_files(repo):
        relative = path.relative_to(repo).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=relative)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            parse_errors.append({"file": relative, "error": str(exc)})
            continue
        visitor = SecurityVisitor(relative, source)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    findings.sort(key=lambda item: (item["file"], item["line"], item["check"]))
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"AST-{index:04d}"
    return findings, parse_errors


def _bandit_command() -> list[str] | None:
    executable = shutil.which("bandit")
    if executable:
        return [executable]
    if importlib.util.find_spec("bandit") is not None:
        return [sys.executable, "-m", "bandit"]
    return None


def bandit_version() -> str | None:
    command = _bandit_command()
    if command is None:
        return None
    try:
        completed = subprocess.run(
            [*command, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    lines = [line.strip() for line in (completed.stdout + completed.stderr).splitlines() if line.strip()]
    return lines[0] if lines else None


def _bandit_exclusions(repo: Path) -> list[Path]:
    exclusions: list[Path] = []
    for root, directories, _ in os.walk(repo):
        skipped = sorted(name for name in directories if name in SKIP_DIRS)
        exclusions.extend(Path(root) / name for name in skipped)
        directories[:] = [name for name in directories if name not in SKIP_DIRS]
    return exclusions


def run_bandit(repo: Path) -> dict[str, Any]:
    command = _bandit_command()
    exclusions = _bandit_exclusions(repo)
    relative_exclusions = [path.relative_to(repo).as_posix() for path in exclusions]
    if command is None:
        return {
            "available": False,
            "count": None,
            "findings": [],
            "error": "Bandit is not installed.",
            "warnings": None,
            "excluded_paths": relative_exclusions,
        }
    arguments = [*command, "-r", str(repo), "-f", "json", "-q"]
    if exclusions:
        arguments.extend(["-x", ",".join(str(path) for path in exclusions)])
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "available": True,
            "count": None,
            "findings": [],
            "error": str(exc),
            "warnings": None,
            "excluded_paths": relative_exclusions,
        }
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return {
            "available": True,
            "count": None,
            "findings": [],
            "error": completed.stderr.strip() or "Bandit returned invalid JSON.",
            "warnings": None,
            "excluded_paths": relative_exclusions,
        }
    findings = payload.get("results") or []
    return {
        "available": True,
        "count": len(findings),
        "findings": findings,
        "error": None,
        "warnings": completed.stderr.strip() or None,
        "excluded_paths": relative_exclusions,
    }


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required. Install requirements.txt.") from exc
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"Invalid configuration: {path}")
    return data


def build_context(repo: Path, finding: dict[str, Any], radius: int = 12) -> str:
    source = (repo / finding["file"]).read_text(encoding="utf-8").splitlines()
    line = int(finding["line"])
    start = max(1, line - radius)
    end = min(len(source), line + radius)
    excerpt = "\n".join(f"{number:>5}: {source[number - 1]}" for number in range(start, end + 1))
    return (
        "Repair this defensive Python security finding with the smallest safe change.\n"
        "Return exactly a JSON object with exactly these string keys: finding_id, summary, patch.\n"
        "patch must be a unified diff against the repository root, modify only the named file, "
        "and must not add dependencies or unrelated cleanup. Do not include markdown fences.\n\n"
        f"Finding ID: {finding['id']}\n"
        f"Check: {finding['check']}\n"
        f"File: {finding['file']}\n"
        f"Line: {finding['line']}\n"
        f"Message: {finding['message']}\n\n"
        f"Source context:\n{excerpt}\n"
    )


def build_retry_context(
    repo: Path,
    finding: dict[str, Any],
    rejected_output: str,
    rejection_reason: str,
    retry_number: int,
) -> str:
    source = (repo / finding["file"]).read_text(encoding="utf-8")
    return (
        "Correct a rejected defensive patch. Return exactly a JSON object with exactly these "
        "string keys: finding_id, summary, patch. Do not include markdown fences.\n"
        "The patch must be a minimal unified diff against the exact current file below, modify "
        "only that file, preserve unrelated behavior, and add no dependencies. Hunk context must "
        "match the supplied file byte-for-byte. Do not reuse incorrect line numbers or context "
        "from the rejected output.\n\n"
        f"Retry: {retry_number}\n"
        f"Finding ID: {finding['id']}\n"
        f"Check: {finding['check']}\n"
        f"File: {finding['file']}\n"
        f"Line: {finding['line']}\n"
        f"Message: {finding['message']}\n"
        f"Verifier rejection: {rejection_reason}\n\n"
        f"Rejected model output:\n{rejected_output[-5000:]}\n\n"
        f"Exact current file ({finding['file']}):\n{source}\n"
    )


def validate_model_output(output: Any, finding: dict[str, Any]) -> tuple[str | None, str | None]:
    if not isinstance(output, dict) or set(output) != {"finding_id", "summary", "patch"}:
        return None, "JSON object must contain exactly finding_id, summary, and patch."
    if output["finding_id"] != finding["id"]:
        return None, "finding_id does not match the requested finding."
    if not isinstance(output["summary"], str) or not isinstance(output["patch"], str):
        return None, "summary and patch must be strings."
    patch = output["patch"].strip()
    if not patch:
        return None, "patch is empty."
    return patch + "\n", None


def _patch_paths(patch: str) -> list[str]:
    paths: list[str] = []
    for line in patch.splitlines():
        if not line.startswith("+++ "):
            continue
        raw = line[4:].split("\t", 1)[0].strip()
        if raw.startswith("b/"):
            raw = raw[2:]
        paths.append(raw)
    return paths


def preflight_patch(patch: str, finding: dict[str, Any], repo: Path) -> str | None:
    paths = _patch_paths(patch)
    if paths != [finding["file"]]:
        return "Patch must modify exactly the finding's file."
    pure = PurePosixPath(paths[0])
    if pure.is_absolute() or ".." in pure.parts or pure.suffix != ".py":
        return "Patch path is unsafe or is not a Python file."
    target = repo.joinpath(*pure.parts)
    if not target.is_file() or target.is_symlink():
        return "Patch target must be an existing, non-symlink Python file."
    changed = [
        line for line in patch.splitlines() if line[:1] in {"+", "-"} and not line.startswith(("+++", "---"))
    ]
    if not changed:
        return "git diff is empty."
    if len(changed) > 40:
        return "Patch is not minimal: more than 40 lines are changed."
    added = "\n".join(line[1:] for line in changed if line.startswith("+"))
    if any(pattern.search(added) for pattern in ADDED_BANNED_PATTERNS):
        return "Patch introduces a banned dangerous pattern."
    return None


def _git_apply(repo: Path, patch_path: Path, check_only: bool = False) -> subprocess.CompletedProcess[str]:
    command = ["git", "-c", f"safe.directory={repo}", "apply", "--whitespace=error-all"]
    if check_only:
        command.append("--check")
    command.append(str(patch_path))
    return subprocess.run(command, cwd=repo, capture_output=True, text=True, timeout=60, check=False)


def _copy_ignore(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in SKIP_DIRS}


def _file_hashes(repo: Path) -> dict[str, str]:
    return {
        path.relative_to(repo).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in list_python_files(repo)
    }


def _tests_exist(repo: Path) -> bool:
    return any(
        path.name.startswith("test_") or path.name.endswith("_test.py")
        for path in list_python_files(repo)
    )


def _run_pytest(repo: Path) -> dict[str, Any]:
    if not _tests_exist(repo):
        return {"required": False, "passed": True, "detail": "No tests detected."}
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"required": True, "passed": False, "detail": "pytest timed out after 300 seconds."}
    detail = (completed.stdout + "\n" + completed.stderr).strip()[-4000:]
    return {"required": True, "passed": completed.returncode == 0, "detail": detail}


def _parse_changed_python(repo: Path, paths: list[str]) -> tuple[bool, str]:
    for relative in paths:
        try:
            source = (repo / relative).read_text(encoding="utf-8")
            ast.parse(source, filename=relative)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            return False, f"{relative}: {exc}"
    return True, "All changed Python files parse."


def _verify_patch(repo: Path, patch: str, finding: dict[str, Any], baseline_bandit: dict[str, Any]) -> dict[str, Any]:
    preflight_error = preflight_patch(patch, finding, repo)
    if preflight_error:
        return {"accepted": False, "reason": preflight_error}
    with tempfile.TemporaryDirectory(prefix="pysecpatch-verify-") as temp_name:
        worktree = Path(temp_name) / "repo"
        shutil.copytree(repo, worktree, symlinks=True, ignore=_copy_ignore)
        before_hashes = _file_hashes(worktree)
        original_bytes = (worktree / finding["file"]).read_bytes()
        patch_path = Path(temp_name) / "candidate.patch"
        patch_path.write_text(patch, encoding="utf-8")
        check = _git_apply(worktree, patch_path, check_only=True)
        if check.returncode != 0:
            return {"accepted": False, "reason": f"git apply --check failed: {check.stderr.strip()}"}
        applied = _git_apply(worktree, patch_path)
        if applied.returncode != 0:
            return {"accepted": False, "reason": f"git apply failed: {applied.stderr.strip()}"}

        after_hashes = _file_hashes(worktree)
        changed_paths = sorted(
            path for path in set(before_hashes) | set(after_hashes) if before_hashes.get(path) != after_hashes.get(path)
        )
        if changed_paths != [finding["file"]]:
            return {"accepted": False, "reason": "Clean Python files were rewritten.", "changed_paths": changed_paths}
        parsed, parse_detail = _parse_changed_python(worktree, changed_paths)
        if not parsed:
            return {"accepted": False, "reason": f"AST parse failed: {parse_detail}"}

        original_copy = Path(temp_name) / "original.py"
        original_copy.write_bytes(original_bytes)
        diff = subprocess.run(
            ["git", "diff", "--no-index", "--", str(original_copy), str(worktree / finding["file"])],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if diff.returncode != 1 or not diff.stdout.strip():
            return {"accepted": False, "reason": "git diff is empty or could not be generated."}

        before_findings, _ = scan_ast(repo)
        after_findings, _ = scan_ast(worktree)
        before_counts = Counter(item["check"] for item in before_findings)
        after_counts = Counter(item["check"] for item in after_findings)
        introduced = sorted(check for check, count in after_counts.items() if count > before_counts[check])
        if introduced:
            return {"accepted": False, "reason": f"Dangerous AST patterns increased: {', '.join(introduced)}"}
        pytest_result = _run_pytest(worktree)
        if not pytest_result["passed"]:
            return {"accepted": False, "reason": "pytest failed.", "pytest": pytest_result}

        bandit_after = run_bandit(worktree)
        if baseline_bandit.get("count") is not None:
            if bandit_after.get("count") is None:
                return {"accepted": False, "reason": "Bandit verification could not produce a finding count."}
            if bandit_after["count"] > baseline_bandit["count"]:
                return {"accepted": False, "reason": "Bandit finding count increased.", "bandit_after": bandit_after["count"]}

        return {
            "accepted": True,
            "reason": "Patch passed all applicable acceptance checks.",
            "changed_paths": changed_paths,
            "ast_parse": parse_detail,
            "pytest": pytest_result,
            "bandit_before": baseline_bandit.get("count"),
            "bandit_after": bandit_after.get("count"),
            "bandit_comparison_skipped": baseline_bandit.get("count") is None,
        }


def apply_verified_patch(repo: Path, patch: str, finding: dict[str, Any]) -> tuple[bool, str]:
    before_hashes = _file_hashes(repo)
    with tempfile.NamedTemporaryFile("w", suffix=".patch", encoding="utf-8", delete=False) as handle:
        handle.write(patch)
        patch_path = Path(handle.name)
    try:
        check = _git_apply(repo, patch_path, check_only=True)
        if check.returncode != 0:
            return False, f"Final git apply --check failed: {check.stderr.strip()}"
        applied = _git_apply(repo, patch_path)
        if applied.returncode != 0:
            return False, f"Final git apply failed: {applied.stderr.strip()}"
    finally:
        patch_path.unlink(missing_ok=True)
    after_hashes = _file_hashes(repo)
    changed = sorted(path for path in set(before_hashes) | set(after_hashes) if before_hashes.get(path) != after_hashes.get(path))
    if changed != [finding["file"]]:
        return False, f"Unexpected final changed files: {changed}"
    return True, "Applied verified patch."


@contextmanager
def repository_target(repo_path: str | None, github_url: str | None) -> Iterator[tuple[Path, str]]:
    if repo_path:
        repo = Path(repo_path).expanduser().resolve()
        if not repo.is_dir():
            raise RuntimeError(f"Local repository does not exist: {repo}")
        yield repo, str(repo)
        return
    assert github_url is not None
    if not GITHUB_RE.fullmatch(github_url):
        raise RuntimeError("--github must be an explicit https://github.com/OWNER/REPO URL.")
    with tempfile.TemporaryDirectory(prefix="pysecpatch-clone-") as temp_name:
        repo = Path(temp_name) / "repo"
        completed = subprocess.run(
            ["git", "clone", "--depth", "1", "--", github_url, str(repo)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"GitHub clone failed: {completed.stderr.strip()}")
        yield repo, github_url


def run_agent(
    args: argparse.Namespace,
    model_instance: TransformersRepairModel | None = None,
    write_reports: bool = True,
) -> dict[str, Any]:
    config = load_config()
    with repository_target(args.repo, args.github) as (repo, target_label):
        python_files = list_python_files(repo)
        findings, parse_errors = scan_ast(repo, python_files)
        bandit = run_bandit(repo)
        attempts: list[dict[str, Any]] = []
        accepted = 0
        rejected = 0
        model = model_instance
        model_error: str | None = None

        if findings and not args.no_model and model is None:
            try:
                model = TransformersRepairModel(
                    args.model or str(config["base_model"]),
                    args.adapter if args.adapter is not None else config.get("adapter_path"),
                    int(config.get("max_seq_len", 4096)),
                )
            except Exception as exc:
                model_error = str(exc)

        for finding in findings:
            if args.no_model:
                break
            if model is None:
                attempts.append(
                    {
                        "finding_id": finding["id"],
                        "invalid_json": False,
                        "accepted": False,
                        "reason": f"Model unavailable: {model_error}",
                    }
                )
                rejected += 1
                continue
            prompt = build_context(repo, finding)
            finding_accepted = False
            for retry_index in range(3):
                inference = model.infer(prompt, max_new_tokens=args.max_new_tokens)
                attempt = {
                    "finding_id": finding["id"],
                    "retry_index": retry_index,
                    "invalid_json": inference["invalid_json"],
                    "raw_output": inference["raw_output"],
                    "accepted": False,
                }
                patch: str | None = None
                if inference["invalid_json"]:
                    attempt["reason"] = inference.get("json_error", "Model output is invalid JSON.")
                else:
                    patch, error = validate_model_output(inference["output"], finding)
                    if error:
                        attempt["reason"] = error
                    elif not args.fix:
                        assert patch is not None
                        attempt["reason"] = "Patch proposed but not applied because --fix was not passed."
                        attempt["proposed_patch"] = patch
                    else:
                        assert patch is not None
                        verification = _verify_patch(repo, patch, finding, bandit)
                        attempt["verification"] = verification
                        attempt["reason"] = verification["reason"]
                        if verification["accepted"]:
                            applied, detail = apply_verified_patch(repo, patch, finding)
                            attempt["accepted"] = applied
                            attempt["reason"] = detail if not applied else verification["reason"]
                            if applied:
                                finding_accepted = True
                                accepted += 1
                                bandit = run_bandit(repo)
                attempts.append(attempt)
                if finding_accepted or not args.fix:
                    break
                if retry_index < 2:
                    prompt = build_retry_context(
                        repo,
                        finding,
                        inference["raw_output"],
                        str(attempt["reason"]),
                        retry_index + 1,
                    )
            if not finding_accepted and args.fix:
                rejected += 1

        final_findings, final_parse_errors = scan_ast(repo)
        final_bandit = run_bandit(repo)
        report = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target_label,
            "source": "github" if args.github else "local",
            "fix_requested": args.fix,
            "model": args.model or config.get("base_model"),
            "adapter": args.adapter if args.adapter is not None else config.get("adapter_path"),
            "summary": {
                "python_files": len(python_files),
                "ast_findings": len(findings),
                "final_ast_findings": len(final_findings),
                "bandit_findings": final_bandit.get("count"),
                "accepted_patches": accepted,
                "rejected_patches": rejected,
            },
            "python_files": [path.relative_to(repo).as_posix() for path in python_files],
            "findings": findings,
            "bandit": final_bandit,
            "repair_attempts": attempts,
            "verification": {
                "initial_parse_errors": parse_errors,
                "final_parse_errors": final_parse_errors,
                "bandit_available": final_bandit["available"],
                "model_error": model_error,
            },
        }
    if write_reports:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        JSON_REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        write_agent_markdown(report, MARKDOWN_REPORT)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan an explicitly selected Python repository and optionally apply verified repairs."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--repo", help="path to a local repository")
    target.add_argument("--github", help="explicit https://github.com/OWNER/REPO URL")
    parser.add_argument("--fix", action="store_true", help="apply only patches that pass every acceptance check")
    parser.add_argument("--model", help="Transformers model ID or local model path")
    parser.add_argument("--adapter", help="optional local LoRA adapter path")
    parser.add_argument("--no-model", action="store_true", help="run scanners and reporting without inference")
    parser.add_argument("--max-new-tokens", type=int, default=900)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.fix and args.no_model:
        parser.error("--fix cannot be combined with --no-model")
    try:
        report = run_agent(args)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps({"report": str(JSON_REPORT), "summary": report["summary"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
