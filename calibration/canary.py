"""Canary server: serves pages whose security headers are fixed by the profile name.

Every profile has a hand-written expected verdict (see PROFILES[x]["expected"]).
This is the ground truth the tool under test is measured against; Observatory is
the independent second opinion for the same URL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

app = FastAPI(title="AIE483 calibration canary", docs_url=None, redoc_url=None)


@dataclass
class Profile:
    """One canary page with a known-correct verdict."""

    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookie: dict[str, Any] | None = None
    # expected verdicts are the hand-written ground truth from the rubrics
    expected: dict[str, Any] = field(default_factory=dict)


_CSP_STRONG = (
    "default-src 'self'; script-src 'self'; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'self'"
)

PROFILES: dict[str, Profile] = {
    # ---- fully hardened: everything present and strong -------------------
    "hardened": Profile(
        name="hardened",
        headers={
            "Content-Security-Policy": _CSP_STRONG,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        },
        cookie={
            "key": "sid",
            "value": "canary-value",
            "httponly": True,
            "secure": False,  # canary runs on plain http; see note below
            "samesite": "strict",
        },
        expected={
            "security_headers": "pass",
            "clickjacking_defense": "pass",
            "cookie_hygiene": "warn",  # Secure cannot be set over plain http
        },
    ),
    # ---- the bug case: core 3 present, Permissions-Policy + COOP absent --
    "missing_permissions_and_coop": Profile(
        name="missing_permissions_and_coop",
        headers={
            "Content-Security-Policy": _CSP_STRONG,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-Frame-Options": "DENY",
        },
        expected={
            # hand-written ground truth: two required headers are absent,
            # so this must NOT be reported as a clean pass
            "security_headers": "warn",
        },
    ),
    # ---- only COOP missing ----------------------------------------------
    "missing_coop_only": Profile(
        name="missing_coop_only",
        headers={
            "Content-Security-Policy": _CSP_STRONG,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "X-Frame-Options": "DENY",
        },
        expected={"security_headers": "warn"},
    ),
    # ---- nothing at all --------------------------------------------------
    "bare": Profile(
        name="bare",
        headers={},
        expected={
            "security_headers": "fail",
            "clickjacking_defense": "fail",
            "cookie_hygiene": "info",  # no cookies observed at all
        },
    ),
    # ---- weak CSP with unsafe-inline -------------------------------------
    "csp_unsafe_inline": Profile(
        name="csp_unsafe_inline",
        headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "X-Frame-Options": "DENY",
        },
        expected={"security_headers": "warn"},
    ),
    # ---- cookies with no flags at all -----------------------------------
    "insecure_cookies": Profile(
        name="insecure_cookies",
        headers={"Cache-Control": "no-store"},
        cookie={
            "key": "session",
            "value": "canary-value",
            "httponly": False,
            "secure": False,
            "samesite": None,
        },
        expected={"cookie_hygiene": "fail"},
    ),
    # ---- X-Frame-Options absent but CSP frame-ancestors present ---------
    "clickjacking_via_csp": Profile(
        name="clickjacking_via_csp",
        headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        },
        expected={"clickjacking_defense": "pass"},
    ),
    # ---- no security.txt but page is otherwise fine ---------------------
    "no_security_txt": Profile(
        name="no_security_txt",
        headers={"Cache-Control": "no-store"},
        expected={"security_metadata": "info"},
    ),
}


def _render_body(profile: Profile) -> str:
    """Minimal HTML body; some checks look for forms and scripts."""
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>canary {profile.name}</title></head><body>"
        f"<h1>canary {profile.name}</h1></body></html>"
    )


@app.get("/canary/{name}", response_class=HTMLResponse)
async def canary(name: str) -> Response:
    """Serve one canary profile."""
    profile = PROFILES.get(name)
    if profile is None:
        return JSONResponse({"error": f"unknown profile: {name}", "known": list(PROFILES)}, status_code=404)

    response: Response = HTMLResponse(content=_render_body(profile))
    for key, value in profile.headers.items():
        response.headers[key] = value
    if profile.cookie:
        response.set_cookie(**profile.cookie)
    return response


@app.get("/canary/{name}/meta", response_class=JSONResponse)
async def canary_meta(name: str) -> Response:
    """Expose the hand-written ground truth for the calibration harness."""
    profile = PROFILES.get(name)
    if profile is None:
        return JSONResponse({"error": f"unknown profile: {name}"}, status_code=404)
    return JSONResponse(
        {
            "name": profile.name,
            "headers": profile.headers,
            "has_cookie": profile.cookie is not None,
            "expected": profile.expected,
        }
    )


@app.get("/profiles", response_class=JSONResponse)
async def profiles() -> Response:
    """List every canary profile name."""
    return JSONResponse({"profiles": sorted(PROFILES)})


@app.get("/wellknown/status")
async def wellknown_status() -> Response:
    """Utility endpoint used by the harness to confirm the server is alive."""
    return JSONResponse({"status": "ok", "profiles": len(PROFILES)})
