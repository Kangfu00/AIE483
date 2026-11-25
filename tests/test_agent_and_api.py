"""End-to-end API, Playwright live inspection, SSE streaming, and AI fallback tests."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright

from app.main import app
from app.recon import _launch_chromium


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
            page.click(".ai-settings summary")
            page.select_option("#ai-provider", "offline")
            page.click(".ai-settings summary")

            # Verify draggable Pixel Spider mascot roams 2D, cycles emotes on click, and drags cleanly
            spider = page.locator("#pixel-spider")
            assert spider.is_visible()
            box_start = spider.bounding_box()
            page.wait_for_timeout(350)
            box_after = spider.bounding_box()
            assert box_start is not None and box_after is not None
            assert box_start["width"] >= 80
            assert box_after["x"] != box_start["x"] or box_after["y"] != box_start["y"]

            # Click triggers inspecting emote, second click triggers reading book emote
            spider.click(force=True)
            assert "emote-inspecting" in (spider.get_attribute("class") or "")
            assert page.locator("#spider-bubble").is_visible()
            spider.click(force=True)
            assert "emote-reading" in (spider.get_attribute("class") or "")

            # Drag spider to a new position via pointer events
            drag_box = spider.bounding_box()
            assert drag_box is not None
            cx = drag_box["x"] + drag_box["width"] / 2
            cy = drag_box["y"] + drag_box["height"] / 2
            page.mouse.move(cx, cy)
            page.mouse.down()
            page.mouse.move(180, 260, steps=6)
            page.mouse.up()
            dropped_box = spider.bounding_box()
            assert dropped_box is not None
            assert abs((dropped_box["x"] + dropped_box["width"] / 2) - 180) < 35
            assert abs((dropped_box["y"] + dropped_box["height"] / 2) - 260) < 35

            # Trigger web shot and verify silk strand + pixel cobweb SVG appear
            page.click("#btn-spider-web")
            assert page.locator("#spider-web-svg .pixel-web-shot").count() >= 1
            assert page.locator("#spider-web-svg .pixel-cobweb").count() >= 1

            page.click("#btn-demo-weak")
            assert "/demo/vulnerable-config" in page.input_value("#target-url")

            page.click("#btn-analyze")
            page.wait_for_selector("#section-plan:not(.hidden)", timeout=15000)
            assert page.locator("#section-input").is_hidden()
            assert "emote-reading" in (spider.get_attribute("class") or "")
            assert page.locator("#agent-trace-box").is_visible()
            page.click("#agent-trace-box summary")
            assert page.locator("#agent-trace-list .trace-item").count() >= 1

            # Reorder second item upward using the UI button
            second_up_btn = page.locator('#recommended-checks-list button[data-move-up="1"]')
            second_up_btn.click()
            assert "emote-shield" in (spider.get_attribute("class") or "")

            page.click("#btn-execute")
            page.wait_for_selector("#section-report:not(.hidden)", timeout=20000)
            assert page.locator("#section-input").is_hidden()
            assert page.locator("#section-plan").is_hidden()
            assert page.locator("#section-progress").is_hidden()

            score_text = page.inner_text("#report-score")
            grade_text = page.inner_text("#report-grade")
            assert score_text.isdigit()
            assert grade_text in {"A", "B", "C", "D", "F"}
            assert page.locator("#report-results-list .result-card").count() >= 1
            assert page.locator("#report-stack-box").is_visible()

            # Verify History drawer shows saved report
            page.click("#btn-history")
            page.wait_for_selector("#section-history:not(.hidden)", timeout=5000)
            assert page.locator("#history-list .history-row").count() >= 1
            page.click("#btn-close-history")
            spider_cls = spider.get_attribute("class") or ""
            assert any(em in spider_cls for em in ("emote-happy", "emote-reading", "emote-shield"))

            # Verify wizard Back navigation (Step 4 -> Step 2 -> Step 1 -> Step 2 via stepper)
            page.click("#btn-back-to-plan")
            page.wait_for_selector("#section-plan:not(.hidden)", timeout=5000)
            assert page.locator("#section-report").is_hidden()

            page.click("#btn-back-to-input")
            page.wait_for_selector("#section-input:not(.hidden)", timeout=5000)
            assert page.locator("#section-plan").is_hidden()

            page.click('.step-pill[data-step="4"]')
            page.wait_for_selector("#section-report:not(.hidden)", timeout=5000)
        finally:
            browser.close()

    assert console_errors == []
    assert page_errors == []
