"""SQLite persistence for passive audit reports and before/after comparisons."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.config import get_db_path
from app.models import CheckDiffItem, ReportDiff, ReportHistoryItem, SecurityReport


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    resolved = db_path or get_db_path()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(resolved))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            target_url TEXT NOT NULL,
            final_url TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            overall_score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            ai_mode_used TEXT NOT NULL,
            checks_count INTEGER NOT NULL,
            report_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_reports_final_url_date ON reports (final_url, generated_at DESC)"
    )
    return conn


def init_db(db_path: Path | None = None) -> None:
    """Initialize SQLite schema if not already created."""
    with _connect(db_path) as conn:
        conn.commit()


def save_report(report: SecurityReport, db_path: Path | None = None) -> None:
    """Persist a generated SecurityReport into SQLite."""
    payload = report.model_dump_json()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO reports (
                report_id, session_id, target_url, final_url, generated_at,
                overall_score, grade, ai_mode_used, checks_count, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.report_id,
                report.session_id,
                report.target_url,
                report.final_url,
                report.generated_at,
                report.overall_score,
                report.grade,
                report.ai_mode_used,
                len(report.results),
                payload,
            ),
        )
        conn.commit()


def get_report(report_id: str, db_path: Path | None = None) -> SecurityReport | None:
    """Load one saved SecurityReport by report_id."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT report_json FROM reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()
    if row is None:
        return None
    return SecurityReport.model_validate_json(row["report_json"])


def list_reports(limit: int = 20, db_path: Path | None = None) -> list[ReportHistoryItem]:
    """List recent saved reports ordered newest-first."""
    safe_limit = max(1, min(100, limit))
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT report_id, target_url, final_url, generated_at,
                   overall_score, grade, ai_mode_used, checks_count
            FROM reports
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    return [
        ReportHistoryItem(
            report_id=row["report_id"],
            target_url=row["target_url"],
            final_url=row["final_url"],
            generated_at=row["generated_at"],
            overall_score=int(row["overall_score"]),
            grade=row["grade"],
            ai_mode_used=row["ai_mode_used"],
            checks_count=int(row["checks_count"]),
        )
        for row in rows
    ]


def find_previous_report(
    final_url: str,
    exclude_report_id: str,
    db_path: Path | None = None,
) -> SecurityReport | None:
    """Return the most recent earlier report for the same normalized final_url."""
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT report_json FROM reports
            WHERE final_url = ? AND report_id != ?
            ORDER BY generated_at DESC
            LIMIT 1
            """,
            (final_url, exclude_report_id),
        ).fetchone()
    if row is None:
        return None
    return SecurityReport.model_validate(json.loads(row["report_json"]))


def compute_report_diff(current: SecurityReport, previous: SecurityReport) -> ReportDiff:
    """Compute score delta and per-check improvements/regressions between two reports."""
    prev_by_id = {r.check_id: r for r in previous.results}
    improved: list[CheckDiffItem] = []
    regressed: list[CheckDiffItem] = []
    unchanged = 0

    for cur in current.results:
        prev = prev_by_id.get(cur.check_id)
        if prev is None:
            continue
        delta = cur.score - prev.score
        item = CheckDiffItem(
            check_id=cur.check_id,
            name=cur.name,
            previous_status=prev.status,
            current_status=cur.status,
            previous_score=prev.score,
            current_score=cur.score,
            score_delta=delta,
        )
        if delta > 0:
            improved.append(item)
        elif delta < 0:
            regressed.append(item)
        else:
            unchanged += 1

    return ReportDiff(
        previous_report_id=previous.report_id,
        previous_generated_at=previous.generated_at,
        previous_score=previous.overall_score,
        previous_grade=previous.grade,
        score_delta=current.overall_score - previous.overall_score,
        improved=improved,
        regressed=regressed,
        unchanged_count=unchanged,
    )
