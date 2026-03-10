from __future__ import annotations

from typing import Dict, List


_SEVERITY_COLOR = {
    "critical": "\x1b[31;1m",  # bright red
    "high": "\x1b[31m",
    "medium": "\x1b[33m",
    "low": "\x1b[36m",
}
_RESET = "\x1b[0m"


def _color(text: str, severity: str, enable: bool) -> str:
    if not enable:
        return text
    color = _SEVERITY_COLOR.get(severity.lower())
    return f"{color}{text}{_RESET}" if color else text


def format_human(report: Dict, color: bool = True) -> str:
    lines: List[str] = []
    issues = report.get("issues", [])
    summary = report.get("summary", {})

    lines.append(f"Contract: {report.get('contract_name', 'unknown')}")
    lines.append(
        f"Issues: {summary.get('total_issues', len(issues))} | "
        f"Critical: {summary.get('critical_issues', 0)}"
    )

    if not issues:
        lines.append("No issues detected.")
        return "\n".join(lines)

    lines.append("\nFindings:")
    for idx, issue in enumerate(issues, start=1):
        severity = issue.get("severity", "Medium")
        title = _color(f"[{severity}]", severity, color)
        fn = issue.get("function_name", "unknown")
        lines.append(f"{idx}. {title} {fn}")
        lines.append(f"   Risk: {issue.get('description', '')}")
        lines.append(f"   Fix: {issue.get('recommendation', '')}")
        example = issue.get("example_fix")
        if example:
            lines.append("   Example:")
            for line in example.splitlines():
                lines.append(f"     {line}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
