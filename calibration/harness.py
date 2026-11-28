"""Calibration harness: score canary + real targets with the tool and with
Mozilla's HTTP Observatory, then report agreement per check.

Two corpora:
  * canary  - local pages whose correct verdict is hand-written in
              calibration/canary.py PROFILES[*]["expected"]
  * remote  - public sites scored by Observatory (the independent oracle)

Usage:
  python -m calibration.harness canary
  python -m calibration.harness remote
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import httpx

from app.checks import CHECK_DEFINITIONS, run_single_check
from app.recon import run_passive_recon
from calibration.canary import PROFILES

OUT_DIR = Path(__file__).resolve().parent / "out"
CANARY_BASE = "http://127.0.0.1:8099"
OBSERVATORY = "https://observatory-api.mdn.mozilla.net/api/v2/analyze"

# Real websites for the Observatory comparison. Chosen for header diversity,
# not for any expected outcome.
REMOTE_TARGETS = [
    "example.com",
    "github.com",
    "mozilla.org",
    "cloudflare.com",
    "vercel.com",
    "stripe.com",
    "npmjs.com",
    "python.org",
    "owasp.org",
    "fastapi.tiangolo.com",
    "shopify.com",
    "wikipedia.org",
    "reddit.com",
    "netlify.com",
]

# Mapping from our check ids to the Observatory test keys that measure the
# same thing. Only pairs that genuinely overlap are compared.
OBS_MAP: dict[str, list[str]] = {
    "security_headers": ["content-security-policy", "x-content-type-options", "referrer-policy"],
    "clickjacking_defense": ["x-frame-options"],
    "cookie_hygiene": ["cookies"],
    "mixed_content_sri": ["subresource-integrity"],
    "https_transport": ["strict-transport-security", "redirection"],
    "cors_info_disclosure": ["cross-origin-resource-sharing", "cross-origin-embedder-policy"],
    "security_metadata": [],
    "form_client_hygiene": [],
}


def fetch_observatory(host: str) -> dict[str, Any]:
    """Query the Observatory API for one host."""
    url = f"{OBSERVATORY}?host={urllib.parse.quote(host)}"
    with urllib.request.urlopen(url, timeout=90) as resp:
        return json.load(resp)


async def score_one(url: str, use_playwright: bool = False) -> dict[str, Any]:
    """Run the tool's recon + all checks against one URL."""
    snapshot = await run_passive_recon(url, use_playwright=use_playwright)
    results = {
        cid: run_single_check(cid, snapshot, idx)
        for idx, cid in enumerate(CHECK_DEFINITIONS, start=1)
    }
    return {
        "url": url,
        "final_url": snapshot.final_url,
        "playwright_used": snapshot.playwright_used,
        "status_code": snapshot.status_code,
        "headers": snapshot.response_headers,
        "results": {
            cid: {"status": r.status, "score": r.score, "summary": r.summary}
            for cid, r in results.items()
        },
    }


async def run_canary() -> int:
    """Compare the tool's verdicts against the hand-written ground truth."""
    rows: list[dict[str, Any]] = []
    agree = 0
    total = 0

    for name, profile in PROFILES.items():
        url = f"{CANARY_BASE}/canary/{name}"
        scored = await score_one(url)
        for cid, expected_status in profile.expected.items():
            actual = scored["results"][cid]["status"]
            total += 1
            ok = actual == expected_status
            agree += int(ok)
            rows.append(
                {
                    "profile": name,
                    "check": cid,
                    "expected": expected_status,
                    "actual": actual,
                    "score": scored["results"][cid]["score"],
                    "agree": ok,
                }
            )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "corpus": "canary",
        "agreement": f"{agree}/{total}",
        "agreement_pct": round(100 * agree / total, 1) if total else 0.0,
        "rows": rows,
    }
    (OUT_DIR / "canary_agreement.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"CANARY agreement: {agree}/{total} ({payload['agreement_pct']}%)")
    for row in rows:
        mark = "OK  " if row["agree"] else "FAIL"
        print(
            f"  [{mark}] {row['profile']:<32} {row['check']:<22} "
            f"expected={row['expected']:<5} actual={row['actual']:<5} score={row['score']}"
        )
    return 0 if agree == total else 1


async def run_remote() -> int:
    """Compare the tool's per-check verdicts with Observatory on public sites."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    per_check: dict[str, list[bool]] = {}

    for host in REMOTE_TARGETS:
        url = f"https://{host}"
        try:
            scored = await score_one(url)
        except Exception as exc:  # noqa: BLE001
            print(f"  skip {host}: tool error {type(exc).__name__}: {exc}")
            continue
        try:
            obs = fetch_observatory(host)
        except Exception as exc:  # noqa: BLE001
            print(f"  skip {host}: observatory error {type(exc).__name__}: {exc}")
            continue

        scan = obs.get("scan") or {}
        tests = obs.get("tests") or {}
        for cid, obs_keys in OBS_MAP.items():
            if not obs_keys:
                continue
            # Observatory reports pass=False/True, or None when the test could
            # not run. None is "no verdict", never "fail" — treating it as fail
            # manufactures disagreement that is not real.
            relevant = [k for k in obs_keys if k in tests and tests[k].get("pass") is not None]
            if not relevant:
                continue
            obs_passes = sum(1 for k in relevant if tests[k].get("pass"))
            obs_verdict = "pass" if obs_passes == len(relevant) else ("fail" if obs_passes == 0 else "warn")
            ours = scored["results"][cid]["status"]
            # normalise: our "info"/"error" means we could not judge
            if ours in ("info", "error"):
                comparable = False
                agree = False
            else:
                comparable = True
                agree = ours == obs_verdict
            per_check.setdefault(cid, []).append(agree)
            rows.append(
                {
                    "host": host,
                    "check": cid,
                    "observatory_tests": {k: tests[k].get("pass") for k in relevant},
                    "observatory_verdict": obs_verdict,
                    "tool_status": ours,
                    "tool_score": scored["results"][cid]["score"],
                    "comparable": comparable,
                    "agree": agree,
                }
            )
        print(f"  scored {host}: observatory grade={scan.get('grade')} score={scan.get('score')}")

    summary = {
        cid: f"{sum(v)}/{len(v)}" for cid, v in sorted(per_check.items())
    }
    payload = {"corpus": "remote", "per_check_agreement": summary, "rows": rows}
    (OUT_DIR / "remote_agreement.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\nPER-CHECK AGREEMENT WITH OBSERVATORY:")
    for cid, val in summary.items():
        print(f"  {cid:<24} {val}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="AIE483 scoring calibration harness")
    parser.add_argument("corpus", choices=["canary", "remote"])
    args = parser.parse_args()
    if args.corpus == "canary":
        return asyncio.run(run_canary())
    return asyncio.run(run_remote())


if __name__ == "__main__":
    sys.exit(main())
