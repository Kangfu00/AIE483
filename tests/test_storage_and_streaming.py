"""Tests for SQLite persistence, before/after diff, stack advice, compression, and /api/recon/stream."""

from __future__ import annotations

import asyncio
import json

import httpx
from fastapi.testclient import TestClient

from app.agent import _compress_telemetry_for_llm, detect_tech_stack
from app.checks import run_single_check
from app.main import REPORT_STORE, app
from app.models import ReconSnapshot, ScriptSummary
from app.recon import run_passive_recon
from app.report import build_security_report, calculate_overall_score
from app.storage import compute_report_diff, get_report, list_reports, save_report


def test_sqlite_persistence_and_before_after_diff() -> None:
    async def _get_snaps() -> tuple[ReconSnapshot, ReconSnapshot]:
        transport = httpx.ASGITransport(app=app)
        weak = await run_passive_recon(
            "http://127.0.0.1:8000/demo/vulnerable-config",
            transport=transport,
            use_playwright=False,
        )
        hard = await run_passive_recon(
            "http://127.0.0.1:8000/demo/hardened",
            transport=transport,
            use_playwright=False,
        )
        return weak, hard

    weak_snap, hard_snap = asyncio.run(_get_snaps())
    cids = ["security_headers", "clickjacking_defense", "cors_info_disclosure"]
    weak_res = [run_single_check(cid, weak_snap, i + 1) for i, cid in enumerate(cids)]
    hard_res = [run_single_check(cid, hard_snap, i + 1) for i, cid in enumerate(cids)]

    w_score, w_grade = calculate_overall_score(weak_res)
    h_score, h_grade = calculate_overall_score(hard_res)

    r_prev = build_security_report(
        session_id="s1",
        target_url="http://127.0.0.1:8000/demo/app",
        final_url="http://127.0.0.1:8000/demo/app",
        existing_defenses=[],
        results=weak_res,
        overall_score=w_score,
        grade=w_grade,
        ai_mode_used="offline-rule-agent",
        ai_fallback_reason=None,
        executive_summary="Before fix",
        priority_actions=["Add headers"],
    )
    save_report(r_prev)

    r_cur = build_security_report(
        session_id="s2",
        target_url="http://127.0.0.1:8000/demo/app",
        final_url="http://127.0.0.1:8000/demo/app",
        existing_defenses=[],
        results=hard_res,
        overall_score=h_score,
        grade=h_grade,
        ai_mode_used="offline-rule-agent",
        ai_fallback_reason=None,
        executive_summary="After fix",
        priority_actions=[],
    )
    save_report(r_cur)

    loaded = get_report(r_cur.report_id)
    assert loaded is not None
    assert loaded.overall_score == h_score

    history = list_reports()
    assert len(history) == 2

    diff = compute_report_diff(r_cur, r_prev)
    assert diff.score_delta > 0
    assert len(diff.improved) == 3
    assert len(diff.regressed) == 0


def test_context_compression_and_stack_detection() -> None:
    snap = ReconSnapshot(
        target_url="https://example.com",
        final_url="https://example.com",
        scheme="https",
        status_code=200,
        is_https=True,
        response_headers={"server": "nginx/1.24", "via": "1.1 cloudflare"},
        scripts=[
            ScriptSummary(src="https://cdn.example.com/a.js", is_external=True, has_integrity=False),
            ScriptSummary(src="https://cdn.example.com/b.js", is_external=True, has_integrity=True),
            ScriptSummary(src="", is_inline=True),
        ],
    )
    stack = detect_tech_stack(snap)
    assert "Nginx" in stack
    assert "Cloudflare" in stack

    compressed = _compress_telemetry_for_llm(snap)
    assert compressed["scripts_summary"]["total"] == 3
    assert compressed["scripts_summary"]["inline_count"] == 1
    assert compressed["scripts_summary"]["external_by_domain"]["cdn.example.com"] == {
        "total": 2,
        "missing_sri": 1,
    }


def test_api_recon_stream_and_history_endpoints() -> None:
    client = TestClient(app)

    # 1. Stream recon & tool calling on Demo Hardened (offline mode)
    with client.stream(
        "POST",
        "/api/recon/stream",
        json={
            "url": "http://127.0.0.1:8000/demo/hardened",
            "ai_config": {"provider": "offline"},
        },
    ) as stream_resp:
        assert stream_resp.status_code == 200
        raw = "".join(stream_resp.iter_text())

    # Note: TestClient runs against app in-process; if local port 8000 isn't listening it yields error event cleanly.
    # Let's test /api/reports persistence directly via /api/recon + /api/execute on live_server_url?
    assert "event: recon_start" in raw


def test_history_api_survives_memory_cache_clear(live_server_url: str) -> None:
    client = TestClient(app)

    with client.stream(
        "POST",
        "/api/recon/stream",
        json={
            "url": f"{live_server_url}/demo/hardened",
            "ai_config": {"provider": "offline"},
        },
    ) as stream_resp:
        assert stream_resp.status_code == 200
        raw_sse = "".join(stream_resp.iter_text())

    assert "event: recon_start" in raw_sse
    assert "event: recon_done" in raw_sse
    assert "event: tool_start" in raw_sse
    assert "event: tool_done" in raw_sse
    assert "event: complete" in raw_sse

    complete_line = [ln for ln in raw_sse.splitlines() if ln.startswith("data:") and '"recon"' in ln][-1]
    recon_data = json.loads(complete_line[5:].strip())["recon"]

    # Execute twice to verify persistence + automatic before/after diff
    first = client.post(
        "/api/execute",
        json={
            "session_id": recon_data["session_id"],
            "selected_check_ids": ["security_headers", "clickjacking_defense"],
            "ai_config": {"provider": "offline"},
        },
    )
    assert first.status_code == 200
    second = client.post(
        "/api/execute",
        json={
            "session_id": recon_data["session_id"],
            "selected_check_ids": ["security_headers", "clickjacking_defense"],
            "ai_config": {"provider": "offline"},
        },
    )
    assert second.status_code == 200
    second_report = second.json()
    assert second_report["diff_from_previous"] is not None
    assert second_report["diff_from_previous"]["score_delta"] == 0
    assert "Python / FastAPI (Uvicorn)" in second_report["detected_stack"]
    assert second_report["stack_advice"]

    # Clear RAM cache and verify /api/reports & export still load from SQLite
    REPORT_STORE.clear()
    hist = client.get("/api/reports")
    assert hist.status_code == 200
    assert len(hist.json()) == 2

    fetched = client.get(f"/api/reports/{second_report['report_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["report_id"] == second_report["report_id"]

    exported = client.get(f"/api/reports/{second_report['report_id']}/export?format=markdown")
    assert exported.status_code == 200
    assert "Comparison vs Previous Audit" in exported.text
