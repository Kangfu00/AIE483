"""FastAPI application for the Passive Web Security Audit Agent prototype."""

from __future__ import annotations

import asyncio
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any, AsyncIterator
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from app.agent import generate_audit_plan, summarize_report
from app.checks import CHECK_DEFINITIONS, run_single_check
from app.config import normalize_and_validate_url
from app.demo import router as demo_router
from app.models import (
    CheckResult,
    ExecutePlanRequest,
    ExistingDefenseItem,
    ReconRequest,
    ReconResponse,
    ReconSnapshot,
    SecurityReport,
)
from app.recon import run_passive_recon
from app.report import build_security_report, calculate_overall_score, report_to_markdown

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_CACHED_ITEMS = 100


class _BoundedStore(OrderedDict[str, Any]):
    """In-memory FIFO-evicting store for prototype sessions and reports."""

    def put(self, key: str, value: Any) -> None:
        if key in self:
            self.move_to_end(key)
        self[key] = value
        while len(self) > MAX_CACHED_ITEMS:
            self.popitem(last=False)


SESSION_STORE: _BoundedStore = _BoundedStore()
REPORT_STORE: _BoundedStore = _BoundedStore()

app = FastAPI(
    title="AI Passive Web Security Auditor",
    description="Prototype AI agent for read-only passive web security posture assessment and reporting.",
    version="1.0.0",
)

app.include_router(demo_router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _sse_event(event_name: str, payload: dict[str, Any]) -> str:
    return f"event: {event_name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _validate_selected_checks(check_ids: list[str]) -> list[str]:
    ordered_unique = list(dict.fromkeys(cid.strip() for cid in check_ids if cid.strip()))
    if not ordered_unique:
        raise HTTPException(status_code=400, detail="กรุณาเลือกอย่างน้อย 1 หัวข้อสำหรับการตรวจสอบ")
    invalid = [cid for cid in ordered_unique if cid not in CHECK_DEFINITIONS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"พบหัวข้อตรวจสอบที่ไม่รู้จัก: {', '.join(invalid)}")
    return ordered_unique


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    """Serve the web application dashboard."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict[str, Any]:
    """Basic health and capability metadata."""
    return {
        "status": "ok",
        "mode": "passive-read-only-audit",
        "checks_available": list(CHECK_DEFINITIONS.keys()),
    }


@app.post("/api/recon", response_model=ReconResponse)
async def api_recon(req: ReconRequest) -> ReconResponse:
    """Run initial passive reconnaissance and let the AI agent prepare an audit plan."""
    try:
        validated_url = normalize_and_validate_url(req.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        snapshot = await run_passive_recon(validated_url)
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="เชื่อมต่อเว็บไซต์เป้าหมายไม่ทันเวลา (Timeout)") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"ไม่สามารถดึงข้อมูลจากเว็บไซต์เป้าหมายได้ ({type(exc).__name__})",
        ) from exc

    ai_mode, fallback_reason, ai_summary, defenses, recommended = await generate_audit_plan(
        snapshot,
        req.ai_config,
    )

    session_id = str(uuid4())
    SESSION_STORE.put(
        session_id,
        {
            "snapshot": snapshot,
            "existing_defenses": defenses,
        },
    )

    return ReconResponse(
        session_id=session_id,
        snapshot=snapshot,
        ai_mode_used=ai_mode,
        ai_fallback_reason=fallback_reason,
        ai_summary=ai_summary,
        existing_defenses=defenses,
        recommended_checks=recommended,
    )


async def _execute_and_build_report(
    *,
    session_id: str,
    snapshot: ReconSnapshot,
    defenses: list[ExistingDefenseItem],
    ordered_ids: list[str],
    req: ExecutePlanRequest,
) -> SecurityReport:
    results: list[CheckResult] = []
    for idx, cid in enumerate(ordered_ids, start=1):
        results.append(run_single_check(cid, snapshot, idx))

    overall_score, grade = calculate_overall_score(results)
    ai_mode, fallback_reason, exec_summary, priority_actions = await summarize_report(
        snapshot.final_url,
        overall_score,
        grade,
        results,
        req.ai_config,
    )
    report = build_security_report(
        session_id=session_id,
        target_url=snapshot.target_url,
        final_url=snapshot.final_url,
        existing_defenses=defenses,
        results=results,
        overall_score=overall_score,
        grade=grade,
        ai_mode_used=ai_mode,
        ai_fallback_reason=fallback_reason,
        executive_summary=exec_summary,
        priority_actions=priority_actions,
    )
    REPORT_STORE.put(report.report_id, report)
    return report


@app.post("/api/execute", response_model=SecurityReport)
async def api_execute(req: ExecutePlanRequest) -> SecurityReport:
    """Execute user-selected passive checks in order and return the final report."""
    session_data = SESSION_STORE.get(req.session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="ไม่พบ Session การวิเคราะห์เบื้องต้น กรุณาวิเคราะห์ URL ใหม่อีกครั้ง")

    ordered_ids = _validate_selected_checks(req.selected_check_ids)
    return await _execute_and_build_report(
        session_id=req.session_id,
        snapshot=session_data["snapshot"],
        defenses=session_data["existing_defenses"],
        ordered_ids=ordered_ids,
        req=req,
    )


@app.post("/api/execute/stream")
async def api_execute_stream(req: ExecutePlanRequest) -> StreamingResponse:
    """Stream step-by-step ordered check execution progress via SSE."""
    session_data = SESSION_STORE.get(req.session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="ไม่พบ Session การวิเคราะห์เบื้องต้น กรุณาวิเคราะห์ URL ใหม่อีกครั้ง")

    ordered_ids = _validate_selected_checks(req.selected_check_ids)
    snapshot: ReconSnapshot = session_data["snapshot"]
    defenses: list[ExistingDefenseItem] = session_data["existing_defenses"]

    async def event_stream() -> AsyncIterator[str]:
        total = len(ordered_ids)
        yield _sse_event(
            "start",
            {
                "session_id": req.session_id,
                "target_url": snapshot.final_url,
                "total_steps": total,
            },
        )

        results: list[CheckResult] = []
        for idx, cid in enumerate(ordered_ids, start=1):
            defn = CHECK_DEFINITIONS[cid]
            yield _sse_event(
                "check_start",
                {
                    "order_index": idx,
                    "total_steps": total,
                    "check_id": cid,
                    "name": defn.name,
                },
            )
            await asyncio.sleep(0.18)
            res = run_single_check(cid, snapshot, idx)
            results.append(res)
            yield _sse_event(
                "check_done",
                {
                    "order_index": idx,
                    "total_steps": total,
                    "result": res.model_dump(),
                },
            )

        yield _sse_event("summarizing", {"message": "AI Agent กำลังสังเคราะห์รายงานและจัดลำดับคำแนะนำ..."})
        overall_score, grade = calculate_overall_score(results)
        ai_mode, fallback_reason, exec_summary, priority_actions = await summarize_report(
            snapshot.final_url,
            overall_score,
            grade,
            results,
            req.ai_config,
        )
        report = build_security_report(
            session_id=req.session_id,
            target_url=snapshot.target_url,
            final_url=snapshot.final_url,
            existing_defenses=defenses,
            results=results,
            overall_score=overall_score,
            grade=grade,
            ai_mode_used=ai_mode,
            ai_fallback_reason=fallback_reason,
            executive_summary=exec_summary,
            priority_actions=priority_actions,
        )
        REPORT_STORE.put(report.report_id, report)
        yield _sse_event("complete", {"report": report.model_dump()})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/reports/{report_id}/export")
async def api_export_report(
    report_id: str,
    format: str = Query(default="markdown", pattern="^(markdown|json)$"),
) -> Response:
    """Download a generated report in Markdown or JSON format."""
    report: SecurityReport | None = REPORT_STORE.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="ไม่พบรายงานที่ระบุ (อาจหมดอายุหรือถูกล้างจากหน่วยความจำ)")

    if format == "json":
        return JSONResponse(
            content=report.model_dump(),
            headers={"Content-Disposition": f'attachment; filename="security-report-{report_id[:8]}.json"'},
        )

    md_text = report_to_markdown(report)
    return Response(
        content=md_text,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="security-report-{report_id[:8]}.md"'},
    )
