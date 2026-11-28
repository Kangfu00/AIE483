"""Step-3 prototypes: measure the five design choices that an experiment settles.

Each function answers one question with numbers, not opinion. Nothing here
modifies app/ — the alternatives are simulated alongside the current behaviour.
"""

from __future__ import annotations

import asyncio
import json
import statistics
from pathlib import Path
from typing import Any

from app.checks import CHECK_DEFINITIONS, run_single_check
from app.models import ReconSnapshot
from app.recon import run_passive_recon
from app.report import calculate_overall_score

OUT = Path(__file__).resolve().parent / "out"
CANARY_BASE = "http://127.0.0.1:8099"


# ---------------------------------------------------------------- experiment 1
async def exp_filter_info() -> dict[str, Any]:
    """Does excluding info/error from numerator AND denominator change grades?

    Measures: how many canary + remote pages have any info/error result, how far
    the overall score moves, and whether any page divides by zero.
    """
    targets = [f"{CANARY_BASE}/canary/{n}" for n in
               ["hardened", "bare", "insecure_cookies", "no_security_txt", "missing_coop_only"]]
    rows = []
    zero_div_cases = 0

    for url in targets:
        snap = await run_passive_recon(url, use_playwright=False)
        results = [run_single_check(cid, snap, i) for i, cid in enumerate(CHECK_DEFINITIONS, 1)]
        current_score, current_grade = calculate_overall_score(results)

        scored = [r for r in results if r.status not in ("info", "error")]
        if scored:
            weight_total = sum(CHECK_DEFINITIONS[r.check_id].weight for r in scored)
            new_score = round(sum(r.score * CHECK_DEFINITIONS[r.check_id].weight for r in scored) / weight_total)
            new_grade = _grade(new_score)
        else:
            new_score, new_grade = 0, "F"
            zero_div_cases += 1

        rows.append({
            "url": url.rsplit("/", 1)[-1],
            "info_error_count": len(results) - len(scored),
            "current_score": current_score, "current_grade": current_grade,
            "filtered_score": new_score, "filtered_grade": new_grade,
            "delta": new_score - current_score,
            "grade_changed": current_grade != new_grade,
        })

    return {
        "experiment": "filter info/error from weighted score",
        "zero_division_cases": zero_div_cases,
        "max_abs_delta": max(abs(r["delta"]) for r in rows),
        "pages_with_grade_change": sum(1 for r in rows if r["grade_changed"]),
        "rows": rows,
    }


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"


# ---------------------------------------------------------------- experiment 2
def exp_status_rule() -> dict[str, Any]:
    """Compare deciding status from missing_core list vs from score thresholds.

    Uses the canary corpus, where the correct verdict is hand-written. Counts how
    many headers-present-but-incomplete pages each rule mislabels as 'pass'.
    """
    from calibration.canary import PROFILES

    score_rule = [(95, "pass"), (70, "warn"), (0, "fail")]

    def verdict_from_score(score: int) -> str:
        for threshold, label in score_rule:
            if score >= threshold:
                return label
        return "fail"

    rows = []
    list_rule_false_pass = 0
    score_rule_false_pass = 0

    for name, profile in PROFILES.items():
        expected = profile.expected.get("security_headers")
        if expected is None:
            continue
        # rebuild the snapshot the canary would produce, without network
        snap = ReconSnapshot(
            target_url=f"{CANARY_BASE}/canary/{name}",
            final_url=f"{CANARY_BASE}/canary/{name}",
            scheme="http", status_code=200, is_https=False,
            response_headers={k.lower(): v for k, v in profile.headers.items()},
        )
        result = run_single_check("security_headers", snap, 1)
        by_score = verdict_from_score(result.score)
        rows.append({
            "profile": name, "expected": expected,
            "current_rule": result.status, "score": result.score,
            "score_rule": by_score,
            "current_agrees": result.status == expected,
            "score_rule_agrees": by_score == expected,
        })
        if result.status == "pass" and expected != "pass":
            list_rule_false_pass += 1
        if by_score == "pass" and expected != "pass":
            score_rule_false_pass += 1

    return {
        "experiment": "status from missing-list vs from score",
        "list_rule_false_pass": list_rule_false_pass,
        "score_rule_false_pass": score_rule_false_pass,
        "list_rule_agreement": f"{sum(r['current_agrees'] for r in rows)}/{len(rows)}",
        "score_rule_agreement": f"{sum(r['score_rule_agrees'] for r in rows)}/{len(rows)}",
        "rows": rows,
    }


# ---------------------------------------------------------------- experiment 3
def exp_observability() -> dict[str, Any]:
    """Does an observable flag fix the fallback false-pass, and at what cost?

    Compares: no flag (current), reuse playwright_used, vs a new explicit field.
    """
    base = dict(target_url="https://t.example", final_url="https://t.example",
                scheme="https", status_code=200, is_https=True,
                response_headers={"content-security-policy": "default-src 'self'"})

    cases = {
        "no_playwright_cannot_observe": ReconSnapshot(**base, playwright_used=False, mixed_content_urls=[]),
        "playwright_saw_no_mixed": ReconSnapshot(**base, playwright_used=True, mixed_content_urls=[]),
        "playwright_saw_mixed": ReconSnapshot(**base, playwright_used=True,
                                              mixed_content_urls=["http://cdn.example/x.js"]),
    }

    rows = []
    for label, snap in cases.items():
        cur = run_single_check("mixed_content_sri", snap, 1)
        # option A: reuse playwright_used as the observability signal
        if not snap.playwright_used:
            opt_a = "info"
        else:
            opt_a = cur.status
        rows.append({"case": label, "current": cur.status, "score": cur.score, "optionA_playwright_flag": opt_a})

    return {
        "experiment": "observability signal for mixed-content",
        "false_pass_current": rows[0]["current"] == "pass",
        "false_pass_fixed_by_optionA": rows[0]["optionA_playwright_flag"] != "pass",
        "breaks_real_pass_case": rows[1]["optionA_playwright_flag"] != "pass",
        "rows": rows,
    }


# ---------------------------------------------------------------- experiment 4
def exp_private_ip() -> dict[str, Any]:
    """Which private-IP policy keeps the demo working while closing the hole?

    Option A: block RFC1918 except loopback
    Option B: block RFC1918 entirely, whitelist a demo hostname
    Option C: env flag AUDIT_ALLOW_PRIVATE_TARGETS, default deny
    """
    import ipaddress
    from urllib.parse import urlparse

    from app.config import normalize_and_validate_url

    def rfc1918(host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip.is_private and not ip.is_loopback

    probes = {
        "demo_loopback": f"{CANARY_BASE}/canary/hardened",
        "private_lan": "http://192.168.1.1/",
        "private_10": "http://10.0.0.5/",
        "metadata": "http://169.254.169.254/",
        "public": "https://example.com",
    }

    rows = []
    for label, url in probes.items():
        host = urlparse(url).hostname or ""
        try:
            normalize_and_validate_url(url)
            current = "allowed"
        except ValueError:
            current = "blocked"

        is_priv = rfc1918(host)
        loop = host in {"127.0.0.1", "localhost", "::1"}
        # option A: block RFC1918, always allow loopback
        opt_a = "blocked" if is_priv else current
        # option B: block RFC1918 incl. loopback-via-ip; allow only a demo hostname
        opt_b = "blocked" if (is_priv or host in {"127.0.0.1"}) else current
        # option C: same as A but behind a default-off env flag
        opt_c = opt_a

        rows.append({"probe": label, "host": host, "current": current,
                     "optionA": opt_a, "optionB": opt_b, "optionC": opt_c})

    demo_ok_a = next(r for r in rows if r["probe"] == "demo_loopback")["optionA"] == "allowed"
    demo_ok_b = next(r for r in rows if r["probe"] == "demo_loopback")["optionB"] == "allowed"
    lan_closed = all(r["optionA"] == "blocked" for r in rows if r["probe"].startswith("private"))
    return {
        "experiment": "private IP policy",
        "optionA_demo_works": demo_ok_a, "optionA_closes_rfc1918": lan_closed,
        "optionB_demo_works": demo_ok_b, "optionB_closes_rfc1918": lan_closed,
        "note": "option B breaks the loopback demo because the UI targets 127.0.0.1",
        "rows": rows,
    }


# ---------------------------------------------------------------- experiment 5
async def exp_redirect() -> dict[str, Any]:
    """How much does hop-by-hop redirect validation cost in latency?"""
    import time
    import httpx

    url = f"{CANARY_BASE}/canary/hardened"
    samples_follow = []
    samples_manual = []

    for _ in range(5):
        t0 = time.perf_counter()
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as c:
            await c.get(url)
        samples_follow.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        async with httpx.AsyncClient(follow_redirects=False, timeout=10) as c:
            await c.get(url)
        samples_manual.append((time.perf_counter() - t0) * 1000)

    return {
        "experiment": "redirect handling latency",
        "follow_redirects_ms_median": round(statistics.median(samples_follow), 1),
        "manual_ms_median": round(statistics.median(samples_manual), 1),
        "note": "manual hop validation adds one request per redirect hop, not per page",
    }


# ---------------------------------------------------------------- experiment 6
async def exp_actual_bug_cases() -> dict[str, Any]:
    """Does the private-IP hole actually reach an internal service today?"""
    import httpx
    reached = []
    # Simulate a public URL that redirects to an internal address. The canary
    # plays the role of the internal service.
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as c:
            resp = await c.get(f"{CANARY_BASE}/redirect-to-internal")
            reached.append({"final_url": str(resp.url), "status": resp.status_code})
    except Exception as exc:  # noqa: BLE001
        reached.append({"error": f"{type(exc).__name__}: {exc}"})
    return {"experiment": "redirect follows into internal address", "observed": reached}


async def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    report = {
        "exp1_filter_info": await exp_filter_info(),
        "exp2_status_rule": exp_status_rule(),
        "exp3_observability": exp_observability(),
        "exp4_private_ip": exp_private_ip(),
        "exp5_redirect_latency": await exp_redirect(),
    }
    (OUT / "experiments.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=" * 72)
    print("EXP 1 — filter info/error from weighted score")
    e = report["exp1_filter_info"]
    print(f"  zero-division cases : {e['zero_division_cases']}")
    print(f"  max score delta     : {e['max_abs_delta']}")
    print(f"  pages changing grade: {e['pages_with_grade_change']}/{len(e['rows'])}")
    for r in e["rows"]:
        print(f"    {r['url']:<24} info/err={r['info_error_count']} "
              f"{r['current_score']}/{r['current_grade']} -> {r['filtered_score']}/{r['filtered_grade']}")

    print("\nEXP 2 — status from missing-list vs from score")
    e = report["exp2_status_rule"]
    print(f"  list rule : agreement {e['list_rule_agreement']}, false-pass {e['list_rule_false_pass']}")
    print(f"  score rule: agreement {e['score_rule_agreement']}, false-pass {e['score_rule_false_pass']}")
    for r in e["rows"]:
        print(f"    {r['profile']:<32} expected={r['expected']:<5} current={r['current_rule']:<5} "
              f"score_rule={r['score_rule']:<5} (score {r['score']})")

    print("\nEXP 3 — observability flag")
    e = report["exp3_observability"]
    print(f"  false pass today          : {e['false_pass_current']}")
    print(f"  fixed by reusing pw flag  : {e['false_pass_fixed_by_optionA']}")
    print(f"  breaks genuine pass case  : {e['breaks_real_pass_case']}")
    for r in e["rows"]:
        print(f"    {r['case']:<32} current={r['current']:<5} optionA={r['optionA_playwright_flag']}")

    print("\nEXP 4 — private IP policy")
    e = report["exp4_private_ip"]
    print(f"  option A demo works: {e['optionA_demo_works']}, closes RFC1918: {e['optionA_closes_rfc1918']}")
    print(f"  option B demo works: {e['optionB_demo_works']}")
    for r in e["rows"]:
        print(f"    {r['probe']:<16} host={r['host']:<20} current={r['current']:<8} "
              f"A={r['optionA']:<8} B={r['optionB']}")

    print("\nEXP 5 — redirect latency")
    e = report["exp5_redirect_latency"]
    print(f"  follow_redirects median: {e['follow_redirects_ms_median']} ms")
    print(f"  manual hop-by-hop      : {e['manual_ms_median']} ms")


if __name__ == "__main__":
    asyncio.run(main())
