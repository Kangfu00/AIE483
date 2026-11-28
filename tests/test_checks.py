"""Unit tests for URL validation, passive security checks, scoring, and reporting."""

from __future__ import annotations

import asyncio
import itertools

import httpx
import pytest

from app.checks import CHECK_DEFINITIONS, run_single_check
from app.config import normalize_and_validate_url
from app.main import app
from app.recon import ReconSnapshot, run_passive_recon
from app.report import build_security_report, calculate_overall_score, report_to_markdown


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://example.com", "https://example.com"),
        ("example.com/login", "https://example.com/login"),
        ("localhost:8000/demo/hardened", "http://localhost:8000/demo/hardened"),
        ("127.0.0.1:8000/demo/vulnerable-config", "http://127.0.0.1:8000/demo/vulnerable-config"),
    ],
)
def test_normalize_valid_urls(raw: str, expected: str) -> None:
    assert normalize_and_validate_url(raw) == expected


@pytest.mark.parametrize(
    "bad_url",
    [
        "",
        "   ",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://example.com/file",
        "http://user:pass@example.com",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://0.0.0.0:8000",
    ],
)
def test_reject_unsafe_or_invalid_urls(bad_url: str) -> None:
    with pytest.raises(ValueError):
        normalize_and_validate_url(bad_url)


def test_passive_checks_contrast_weak_vs_hardened_demo() -> None:
    async def _run() -> tuple[list, list]:
        transport = httpx.ASGITransport(app=app)
        weak_snap = await run_passive_recon(
            "http://127.0.0.1:8000/demo/vulnerable-config",
            transport=transport,
            use_playwright=False,
        )
        hard_snap = await run_passive_recon(
            "http://127.0.0.1:8000/demo/hardened",
            transport=transport,
            use_playwright=False,
        )
        all_ids = list(CHECK_DEFINITIONS.keys())
        weak_res = [run_single_check(cid, weak_snap, idx + 1) for idx, cid in enumerate(all_ids)]
        hard_res = [run_single_check(cid, hard_snap, idx + 1) for idx, cid in enumerate(all_ids)]
        return weak_res, hard_res

    weak_results, hard_results = asyncio.run(_run())
    weak_by_id = {r.check_id: r for r in weak_results}
    hard_by_id = {r.check_id: r for r in hard_results}

    assert weak_by_id["security_headers"].status == "fail"
    assert weak_by_id["clickjacking_defense"].status == "fail"
    assert weak_by_id["cookie_hygiene"].status == "fail"
    assert weak_by_id["form_client_hygiene"].status == "fail"
    assert weak_by_id["cors_info_disclosure"].status == "warn"

    assert hard_by_id["security_headers"].status == "pass"
    assert hard_by_id["clickjacking_defense"].status == "pass"
    assert hard_by_id["form_client_hygiene"].status in {"pass", "warn"}
    assert hard_by_id["form_client_hygiene"].score > weak_by_id["form_client_hygiene"].score
    assert hard_by_id["cors_info_disclosure"].status == "pass"

    weak_score, weak_grade = calculate_overall_score(weak_results)
    hard_score, _ = calculate_overall_score(hard_results)
    assert hard_score > weak_score
    assert weak_grade in {"D", "F"}


def test_markdown_report_export_format() -> None:
    async def _run() -> str:
        transport = httpx.ASGITransport(app=app)
        snap = await run_passive_recon(
            "http://127.0.0.1:8000/demo/hardened",
            transport=transport,
            use_playwright=False,
        )
        results = [
            run_single_check("security_headers", snap, 1),
            run_single_check("clickjacking_defense", snap, 2),
        ]
        score, grade = calculate_overall_score(results)
        report = build_security_report(
            session_id="sess-1",
            target_url=snap.target_url,
            final_url=snap.final_url,
            existing_defenses=[],
            results=results,
            overall_score=score,
            grade=grade,
            ai_mode_used="offline-rule-agent",
            ai_fallback_reason=None,
            executive_summary="สรุปผลการทดสอบตัวอย่าง",
            priority_actions=["Action 1"],
        )
        return report_to_markdown(report)

    md = asyncio.run(_run())
    assert "# Passive Web Security Posture Report" in md
    assert "| 1 | HTTP Security Headers ตามมาตรฐาน OWASP | `PASS` |" in md
    assert "สรุปผลการทดสอบตัวอย่าง" in md


# --- security_headers status must agree with score (issue #4) -----------------

_FULL_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
    "cross-origin-opener-policy": "same-origin",
}


def _headers_result(headers: dict[str, str]):
    snap = ReconSnapshot(
        target_url="http://127.0.0.1/",
        final_url="http://127.0.0.1/",
        scheme="http",
        status_code=200,
        is_https=False,
        response_headers=headers,
    )
    return run_single_check("security_headers", snap, 1)


@pytest.mark.parametrize(
    "dropped",
    [
        ("cross-origin-opener-policy",),
        ("permissions-policy", "cross-origin-opener-policy"),
    ],
)
def test_security_headers_incomplete_optional_headers_is_not_pass(dropped: tuple[str, ...]) -> None:
    headers = {k: v for k, v in _FULL_HEADERS.items() if k not in dropped}
    result = _headers_result(headers)
    assert result.score < 100
    assert result.status == "warn"


def test_security_headers_complete_is_pass() -> None:
    result = _headers_result(dict(_FULL_HEADERS))
    assert result.score == 100
    assert result.status == "pass"


def test_security_headers_no_pass_below_threshold_any_combination() -> None:
    keys = list(_FULL_HEADERS)
    for present in itertools.product([True, False], repeat=len(keys)):
        for unsafe_inline in (False, True):
            headers = {k: v for k, v, keep in zip(keys, _FULL_HEADERS.values(), present) if keep}
            if unsafe_inline and "content-security-policy" in headers:
                headers["content-security-policy"] = "default-src 'self' 'unsafe-inline'"
            result = _headers_result(headers)
            assert not (result.status == "pass" and result.score < 96), (headers, result.score)
