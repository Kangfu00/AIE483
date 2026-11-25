"""Tests for passive agent tools, safety boundaries, and tool-calling loop."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from app.agent import generate_audit_plan
from app.main import app
from app.models import AIConfigInput
from app.recon import run_passive_recon
from app.tools import ToolContext, execute_passive_tool


def test_passive_tools_enforce_allowlist_and_same_origin() -> None:
    async def _run() -> None:
        transport = httpx.ASGITransport(app=app)
        snap = await run_passive_recon(
            "http://127.0.0.1:8000/demo/vulnerable-config",
            transport=transport,
            use_playwright=False,
        )
        ctx = ToolContext(snapshot=snap, transport=transport)

        # Disallowed tool name rejected
        summary_bad, findings_bad, _ = await execute_passive_tool("run_attack_payload", {}, ctx)
        assert findings_bad.get("allowed") is False
        assert "ปฏิเสธ" in summary_bad

        # CSP parser detects missing CSP on vulnerable demo
        _, csp_missing, _ = await execute_passive_tool("parse_csp_directives", {}, ctx)
        assert csp_missing["present"] is False
        assert "missing_csp" in csp_missing["warnings"]

        # Same-origin subpage tool strictly blocks cross-origin target
        _, blocked_sub, _ = await execute_passive_tool(
            "inspect_same_origin_subpage",
            {"path_or_url": "https://attacker.invalid/secret"},
            ctx,
        )
        assert blocked_sub["inspected"] is False
        assert blocked_sub["reason"] == "cross_origin_blocked"

        # Same-origin subpage tool allows valid same-origin path
        _, ok_sub, _ = await execute_passive_tool(
            "inspect_same_origin_subpage",
            {"path_or_url": "/demo/embed"},
            ctx,
        )
        assert ok_sub["inspected"] is True
        assert ok_sub["url"] == "http://127.0.0.1:8000/demo/embed"

        # Public files & TLS on local HTTP
        _, tls_findings, _ = await execute_passive_tool("inspect_tls_certificate", {}, ctx)
        assert tls_findings["tls_enabled"] is False

        _, pub_findings, _ = await execute_passive_tool("fetch_public_security_files", {}, ctx)
        assert "security_txt" in pub_findings and "robots_txt" in pub_findings

    asyncio.run(_run())


def test_parse_csp_directives_on_hardened_demo() -> None:
    async def _run() -> None:
        transport = httpx.ASGITransport(app=app)
        snap = await run_passive_recon(
            "http://127.0.0.1:8000/demo/hardened",
            transport=transport,
            use_playwright=False,
        )
        ctx = ToolContext(snapshot=snap, transport=transport)
        _, csp_info, _ = await execute_passive_tool("parse_csp_directives", {}, ctx)
        assert csp_info["present"] is True
        assert csp_info["warnings"] == []
        assert "frame-ancestors" in csp_info["directive_names"]

    asyncio.run(_run())


def test_offline_plan_produces_agent_trace() -> None:
    async def _run() -> None:
        transport = httpx.ASGITransport(app=app)
        snap = await run_passive_recon(
            "http://127.0.0.1:8000/demo/hardened",
            transport=transport,
            use_playwright=False,
        )
        mode, fb, _, defenses, recs, trace = await generate_audit_plan(
            snap,
            AIConfigInput(provider="offline"),
            transport=transport,
        )
        assert mode == "offline-rule-agent"
        assert fb is None
        assert len(defenses) >= 3
        assert len(recs) == 8
        assert any(t.tool_name == "parse_csp_directives" for t in trace)

    asyncio.run(_run())


def test_openai_tool_calling_loop_executes_tools_and_synthesizes_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    turn_counter = {"count": 0}
    captured_tool_messages: list[dict[str, Any]] = []

    class _FakeResp:
        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self._payload

    async def fake_post(self: httpx.AsyncClient, url: str, **kwargs: Any) -> _FakeResp:
        turn_counter["count"] += 1
        msgs = kwargs["json"]["messages"]
        if turn_counter["count"] == 1:
            assert "tools" in kwargs["json"]
            return _FakeResp(
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call_csp_1",
                                        "type": "function",
                                        "function": {
                                            "name": "parse_csp_directives",
                                            "arguments": "{}",
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                }
            )

        # Turn 2: verify the tool response was appended to messages
        captured_tool_messages.extend([m for m in msgs if m.get("role") == "tool"])
        plan_json = {
            "ai_summary": "ตรวจสอบ CSP แล้วพบว่าตั้งค่าเข้มแข็งดี",
            "existing_defenses": [
                {
                    "title": "Strong CSP",
                    "category": "HTTP Headers",
                    "evidence": "default-src 'self'",
                    "description": "CSP ป้องกันสคริปต์ภายนอกได้ดี",
                }
            ],
            "recommended_checks": [
                {
                    "id": "https_transport",
                    "priority": "high",
                    "reason": "ทดสอบ HTTPS",
                    "default_selected": True,
                }
            ],
        }
        return _FakeResp({"choices": [{"message": {"role": "assistant", "content": json.dumps(plan_json)}}]})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    async def _run() -> None:
        transport = httpx.ASGITransport(app=app)
        snap = await run_passive_recon(
            "http://127.0.0.1:8000/demo/hardened",
            transport=transport,
            use_playwright=False,
        )
        mode, fb, summary, defenses, recs, trace = await generate_audit_plan(
            snap,
            AIConfigInput(
                provider="openai",
                api_key="dummy-test-key",
                base_url="https://api.example.com/v1",
                model="test-model",
            ),
            transport=transport,
        )
        assert mode == "openai-llm"
        assert fb is None
        assert "ตรวจสอบ CSP" in summary
        assert len(trace) == 1
        assert trace[0].tool_name == "parse_csp_directives"
        assert trace[0].findings["present"] is True
        assert len(captured_tool_messages) == 1
        assert len(defenses) == 1
        assert len(recs) == 8

    asyncio.run(_run())
