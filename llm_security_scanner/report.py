"""Report generation.

Produces a human-readable Markdown report and a machine-readable JSON
report from classified findings.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

from .classifier import SEVERITY_ORDER, ClassifiedFinding

SEVERITY_EMOJI = {
    "CRITICAL": "\U0001F534",
    "HIGH": "\U0001F7E0",
    "MEDIUM": "\U0001F7E1",
    "LOW": "\U0001F535",
    "INFO": "\u26AA",
}


def _sort_key(cf: ClassifiedFinding):
    return -SEVERITY_ORDER.index(cf.severity) if cf.severity in SEVERITY_ORDER else 0


def build_summary(classified: list[ClassifiedFinding], model: str) -> dict:
    total = len(classified)
    flagged = [c for c in classified if c.finding.flagged]
    errors = [c for c in classified if c.finding.error]
    severity_counts = Counter(c.severity for c in flagged)
    category_counts = Counter(
        c.finding.result.case.category_label for c in flagged
    )
    return {
        "model": model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_tests": total,
        "vulnerabilities_found": len(flagged),
        "errors": len(errors),
        "by_severity": dict(severity_counts),
        "by_category": dict(category_counts),
    }


def to_json(classified: list[ClassifiedFinding], model: str) -> str:
    summary = build_summary(classified, model)
    findings_payload = []
    for cf in classified:
        f = cf.finding
        findings_payload.append(
            {
                "id": f.result.case.id,
                "category": f.result.case.category,
                "category_label": f.result.case.category_label,
                "prompt": f.result.case.prompt,
                "response": f.result.response.output_text,
                "flagged": f.flagged,
                "severity": cf.severity,
                "rationale": cf.rationale,
                "matched_markers": f.matched_markers,
                "refusal_detected": f.refusal_detected,
                "error": f.error,
                "latency_s": round(f.result.response.latency_s, 3),
            }
        )
    payload = {"summary": summary, "findings": findings_payload}
    return json.dumps(payload, indent=2)


def to_markdown(classified: list[ClassifiedFinding], model: str) -> str:
    summary = build_summary(classified, model)
    lines: list[str] = []
    lines.append(f"# LLM Security Scan Report")
    lines.append("")
    lines.append(f"**Target model:** `{summary['model']}`  ")
    lines.append(f"**Generated:** {summary['generated_at']}  ")
    lines.append(f"**Total tests run:** {summary['total_tests']}  ")
    lines.append(f"**Vulnerabilities flagged:** {summary['vulnerabilities_found']}  ")
    if summary["errors"]:
        lines.append(f"**Request errors:** {summary['errors']}  ")
    lines.append("")

    if summary["by_severity"]:
        lines.append("## Summary by severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in reversed(SEVERITY_ORDER):
            count = summary["by_severity"].get(sev, 0)
            if count:
                lines.append(f"| {SEVERITY_EMOJI.get(sev, '')} {sev} | {count} |")
        lines.append("")

    if summary["by_category"]:
        lines.append("## Summary by category")
        lines.append("")
        lines.append("| Category | Vulnerabilities |")
        lines.append("|---|---|")
        for cat, count in summary["by_category"].items():
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    flagged = sorted(
        [c for c in classified if c.finding.flagged], key=_sort_key
    )
    if flagged:
        lines.append("## Findings")
        lines.append("")
        for cf in flagged:
            f = cf.finding
            case = f.result.case
            emoji = SEVERITY_EMOJI.get(cf.severity, "")
            lines.append(f"### {emoji} [{cf.severity}] {case.id} - {case.category_label}")
            lines.append("")
            lines.append(f"**Rationale:** {cf.rationale}")
            lines.append("")
            lines.append("**Attack prompt:**")
            lines.append("```")
            lines.append(case.prompt)
            lines.append("```")
            lines.append("")
            lines.append("**Model response (truncated to 500 chars):**")
            lines.append("```")
            lines.append(f.result.response.output_text[:500])
            lines.append("```")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No vulnerabilities were flagged in this scan run.")
        lines.append("")

    errors = [c for c in classified if c.finding.error]
    if errors:
        lines.append("## Request errors")
        lines.append("")
        for cf in errors:
            lines.append(f"- `{cf.finding.result.case.id}`: {cf.finding.error}")
        lines.append("")

    lines.append("---")
    lines.append(
        "_Heuristic scan. Flagged items are leads for manual review, not confirmed exploits. "
        "Unflagged items are not a guarantee of safety._"
    )
    return "\n".join(lines)
