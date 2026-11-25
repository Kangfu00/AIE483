"""Scoring, grading, and Markdown export for passive security reports."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.checks import CHECK_DEFINITIONS
from app.models import CheckResult, ExistingDefenseItem, GradeLevel, SecurityReport


def calculate_overall_score(results: list[CheckResult]) -> tuple[int, GradeLevel]:
    """Compute weighted overall score (0-100) and letter grade."""
    if not results:
        return 0, "F"

    total_weight = 0
    weighted_sum = 0
    for result in results:
        defn = CHECK_DEFINITIONS.get(result.check_id)
        weight = defn.weight if defn else 10
        total_weight += weight
        weighted_sum += result.score * weight

    overall = round(weighted_sum / total_weight) if total_weight > 0 else 0
    overall = max(0, min(100, overall))

    if overall >= 90:
        grade: GradeLevel = "A"
    elif overall >= 80:
        grade = "B"
    elif overall >= 70:
        grade = "C"
    elif overall >= 55:
        grade = "D"
    else:
        grade = "F"
    return overall, grade


def build_security_report(
    *,
    session_id: str,
    target_url: str,
    final_url: str,
    existing_defenses: list[ExistingDefenseItem],
    results: list[CheckResult],
    overall_score: int,
    grade: GradeLevel,
    ai_mode_used: str,
    ai_fallback_reason: str | None,
    executive_summary: str,
    priority_actions: list[str],
) -> SecurityReport:
    """Assemble final SecurityReport object."""
    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0, "error": 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    return SecurityReport(
        report_id=str(uuid4()),
        session_id=session_id,
        target_url=target_url,
        final_url=final_url,
        generated_at=datetime.now(timezone.utc).isoformat(),
        overall_score=overall_score,
        grade=grade,
        counts=counts,
        ai_mode_used=ai_mode_used,
        ai_fallback_reason=ai_fallback_reason,
        executive_summary=executive_summary,
        priority_actions=priority_actions,
        existing_defenses=existing_defenses,
        results=results,
    )


def report_to_markdown(report: SecurityReport) -> str:
    """Render a SecurityReport into clean Markdown for export."""
    lines: list[str] = [
        "# Passive Web Security Posture Report",
        "",
        f"- **Target URL:** `{report.target_url}`",
        f"- **Final URL:** `{report.final_url}`",
        f"- **Generated At (UTC):** `{report.generated_at}`",
        f"- **Overall Score:** **{report.overall_score}/100 (Grade {report.grade})**",
        f"- **AI Agent Mode:** `{report.ai_mode_used}`",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "## Priority Defensive Actions",
        "",
    ]

    for action in report.priority_actions:
        lines.append(f"- {action}")

    lines.extend(["", "## Existing Strong Defenses Observed", ""])
    if report.existing_defenses:
        for defense in report.existing_defenses:
            lines.append(f"- **{defense.title}** (`{defense.category}`): {defense.description} — `{defense.evidence}`")
    else:
        lines.append("- ไม่พบการป้องกันเด่นชัดในการสำรวจเบื้องต้น")

    lines.extend(
        [
            "",
            "## Ordered Check Results",
            "",
            "| # | Check | Status | Score | OWASP Ref |",
            "|---:|---|---|---:|---|",
        ]
    )
    for res in report.results:
        lines.append(
            f"| {res.order_index} | {res.name} | `{res.status.upper()}` | {res.score}/100 | {res.owasp_ref} |"
        )

    for res in report.results:
        lines.extend(
            [
                "",
                f"### {res.order_index}. {res.name} (`{res.status.upper()}` - {res.score}/100)",
                "",
                f"**สรุปผล:** {res.summary}",
                "",
                "**หลักฐานที่ตรวจพบ (Evidence):**",
            ]
        )
        for ev in res.evidence:
            lines.append(f"- `{ev}`")
        if res.recommendations:
            lines.append("")
            lines.append("**คำแนะนำเชิงป้องกัน (Recommendations):**")
            for rec in res.recommendations:
                lines.append(f"- {rec}")
        if res.remediation_snippet:
            lines.extend(["", "**ตัวอย่างการตั้งค่าที่แนะนำ:**", "```", res.remediation_snippet, "```"])

    lines.append("")
    return "\n".join(lines)
