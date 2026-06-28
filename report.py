"""Render PySecPatch JSON evidence as concise Markdown."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def agent_report_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# PySecPatch Agent Report",
        "",
        f"- Target: `{report.get('target', '')}`",
        f"- Mode: `{'fix' if report.get('fix_requested') else 'scan'}`",
        f"- Python files: {summary.get('python_files', 0)}",
        f"- AST findings: {summary.get('ast_findings', 0)}",
        f"- Bandit findings: {summary.get('bandit_findings', 'unavailable')}",
        f"- Accepted patches: {summary.get('accepted_patches', 0)}",
        f"- Rejected patches: {summary.get('rejected_patches', 0)}",
        "",
        "## Findings",
        "",
    ]
    findings = report.get("findings", [])
    if not findings:
        lines.append("No AST findings.")
    else:
        lines.extend(
            (
                "| ID | Check | Severity | Location | Message |",
                "|---|---|---|---|---|",
            )
        )
        for finding in findings:
            location = f"{finding.get('file')}:{finding.get('line')}"
            lines.append(
                "| {id} | {check} | {severity} | {location} | {message} |".format(
                    id=_cell(finding.get("id")),
                    check=_cell(finding.get("check")),
                    severity=_cell(finding.get("severity")),
                    location=_cell(location),
                    message=_cell(finding.get("message")),
                )
            )
    lines.extend(("", "## Repair Attempts", ""))
    attempts = report.get("repair_attempts", [])
    if not attempts:
        lines.append("No model repair attempts were made.")
    else:
        lines.extend(("| Finding | JSON valid | Accepted | Reason |", "|---|---|---|---|"))
        for attempt in attempts:
            lines.append(
                "| {finding} | {valid} | {accepted} | {reason} |".format(
                    finding=_cell(attempt.get("finding_id")),
                    valid=_cell(not attempt.get("invalid_json", False)),
                    accepted=_cell(attempt.get("accepted", False)),
                    reason=_cell(attempt.get("reason", "")),
                )
            )
    lines.extend(("", "## Verification", "", "```json"))
    lines.append(json.dumps(report.get("verification", {}), indent=2))
    lines.extend(("```", ""))
    return "\n".join(lines)


def write_agent_markdown(report: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(agent_report_markdown(report), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a PySecPatch JSON report as Markdown.")
    parser.add_argument("json_report", type=Path)
    parser.add_argument("markdown_report", type=Path, nargs="?")
    args = parser.parse_args()
    output = args.markdown_report or args.json_report.with_suffix(".md")
    report = json.loads(args.json_report.read_text(encoding="utf-8"))
    write_agent_markdown(report, output)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
