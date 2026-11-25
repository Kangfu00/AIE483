"""End-to-end API, Playwright live inspection, SSE streaming, and AI fallback tests."""

from __future__ import annotations

import json
import socket
import threading
import time
from typing import Iterator

import pytest
import uvicorn
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright

from app.main import app
from app.recon import _launch_chromium


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def live_server_url() -> Iterator[str]:
    """Run the FastAPI app in a background uvicorn thread for live Playwright testing."""
    port = _find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)
    else:
        server.should_exit = True
        raise RuntimeError("Live test server failed to start in time")

    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5.0)


def test_static_and_health_endpoints() -> None:
    client = TestClient(app)
    root = client.get("/")
    assert root.status_code == 200
    assert "AI Web Security Posture Agent" in root.text

    health = client.get("/api/health")
    assert health.status_code == 200
    data = health.json()
    assert data["status"] == "ok"
    assert len(data["checks_available"]) == 8


def test_end_to_end_playwright_recon_ordered_execution_and_export(live_server_url: str) -> None:
    client = TestClient(app)

    # 1. Recon on weak demo using live Playwright browser inspection
    recon_resp = client.post(
        "/api/recon",
        json={
            "url": f"{live_server_url}/demo/vulnerable-config",
            "ai_config": {"provider": "offline"},
        },
    )
    assert recon_resp.status_code == 200, recon_resp.text
    recon_data = recon_resp.json()

    snap = recon_data["snapshot"]
    assert snap["playwright_used"] is True
    assert snap["status_code"] == 200
    assert len(snap["forms"]) == 1
    assert snap["forms"][0]["has_password_input"] is True
    assert snap["forms"][0]["is_insecure_action"] is True
    assert any(s["is_external"] and not s["has_integrity"] for s in snap["scripts"])
    assert any(not (lnk["has_noopener"] or lnk["has_noreferrer"]) for lnk in snap["blank_links"])
    assert len(recon_data["recommended_checks"]) == 8

    # 2. Execute subset in explicit custom order via /api/execute
    chosen_order = ["cors_info_disclosure", "mixed_content_sri", "cookie_hygiene", "security_headers"]
    exec_resp = client.post(
        "/api/execute",
        json={
            "session_id": recon_data["session_id"],
            "selected_check_ids": chosen_order,
            "ai_config": {"provider": "offline"},
        },
    )
    assert exec_resp.status_code == 200, exec_resp.text
    report = exec_resp.json()
    assert [r["check_id"] for r in report["results"]] == chosen_order
    assert [r["order_index"] for r in report["results"]] == [1, 2, 3, 4]
    assert report["overall_score"] < 65

    # 3. Stream execution via SSE in different order
    stream_order = ["security_headers", "form_client_hygiene"]
    with client.stream(
        "POST",
        "/api/execute/stream",
        json={
            "session_id": recon_data["session_id"],
            "selected_check_ids": stream_order,
            "ai_config": {"provider": "offline"},
        },
    ) as stream_resp:
        assert stream_resp.status_code == 200
        raw_sse = "".join(stream_resp.iter_text())

    assert "event: start" in raw_sse
    assert "event: check_start" in raw_sse
    assert "event: check_done" in raw_sse
    assert "event: complete" in raw_sse

    complete_line = [
        line for line in raw_sse.splitlines() if line.startswith("data:") and '"report"' in line
    ][-1]
    streamed_report = json.loads(complete_line[5:].strip())["report"]
    assert [r["check_id"] for r in streamed_report["results"]] == stream_order

    # 4. Export Markdown & JSON
    report_id = streamed_report["report_id"]
    md_resp = client.get(f"/api/reports/{report_id}/export?format=markdown")
    assert md_resp.status_code == 200
    assert "# Passive Web Security Posture Report" in md_resp.text

    json_resp = client.get(f"/api/reports/{report_id}/export?format=json")
    assert json_resp.status_code == 200
    assert json_resp.json()["report_id"] == report_id


def test_hardened_demo_recon_and_validation_errors(live_server_url: str) -> None:
    client = TestClient(app)

    recon_resp = client.post(
        "/api/recon",
        json={
            "url": f"{live_server_url}/demo/hardened",
            "ai_config": {"provider": "offline"},
        },
    )
    assert recon_resp.status_code == 200
    data = recon_resp.json()
    defense_titles = [d["title"] for d in data["existing_defenses"]]
    assert any("CSP" in t for t in defense_titles)
    assert any("Clickjacking" in t for t in defense_titles)

    # Bad URL blocked
    bad_url_resp = client.post("/api/recon", json={"url": "javascript:alert(1)"})
    assert bad_url_resp.status_code == 400

    # Unknown session rejected
    bad_sess_resp = client.post(
        "/api/execute",
        json={"session_id": "nonexistent", "selected_check_ids": ["security_headers"]},
    )
    assert bad_sess_resp.status_code == 404

    # Unknown check id rejected
    bad_check_resp = client.post(
        "/api/execute",
        json={"session_id": data["session_id"], "selected_check_ids": ["not_a_real_check"]},
    )
    assert bad_check_resp.status_code == 400


def test_ai_provider_graceful_fallback(live_server_url: str) -> None:
    client = TestClient(app)
    resp = client.post(
        "/api/recon",
        json={
            "url": f"{live_server_url}/demo/hardened",
            "ai_config": {"provider": "gemini", "api_key": ""},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "fallback" in data["ai_mode_used"]
    assert data["ai_fallback_reason"] is not None
    assert len(data["recommended_checks"]) == 8


def test_browser_ui_full_workflow(live_server_url: str) -> None:
    console_errors: list[str] = []
    page_errors: list[str] = []

    with sync_playwright() as p:
        browser, _ = _launch_chromium(p)
        page = browser.new_page()
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda err: page_errors.append(str(err)))

        try:
            page.goto(live_server_url, wait_until="networkidle")
            page.click("#btn-demo-weak")
            assert "/demo/vulnerable-config" in page.input_value("#target-url")

            page.click("#btn-analyze")
            page.wait_for_selector("#section-plan:not(.hidden)", timeout=15000)

            # Reorder second item upward using the UI button
            second_up_btn = page.locator('#recommended-checks-list button[data-move-up="1"]')
            second_up_btn.click()

            page.click("#btn-execute")
            page.wait_for_selector("#section-report:not(.hidden)", timeout=20000)

            score_text = page.inner_text("#report-score")
            grade_text = page.inner_text("#report-grade")
            assert score_text.isdigit()
            assert grade_text in {"A", "B", "C", "D", "F"}
            assert page.locator("#report-results-list .result-card").count() >= 1
        finally:
            browser.close()

    assert console_errors == []
    assert page_errors == []
