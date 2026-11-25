"""Built-in local demo pages with contrasting security configurations."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

router = APIRouter(prefix="/demo", tags=["demo"])


@router.get("/assets/helper.js")
async def demo_helper_js() -> Response:
    """Serve a harmless static JS snippet for local sandbox demos."""
    return Response(
        content='/* Harmless demo helper script */\nwindow.__demoHelperLoaded = true;\n',
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=60"},
    )


@router.get("/embed", response_class=HTMLResponse)
async def demo_embed() -> HTMLResponse:
    """Serve a minimal embeddable page for demo iframe inspection."""
    return HTMLResponse(
        content="<!doctype html><html><body><p>Demo embedded widget</p></body></html>"
    )


@router.get("/vulnerable-config", response_class=HTMLResponse)
async def demo_vulnerable_config(request: Request) -> HTMLResponse:
    """Serve a safe local demo page illustrating weak defensive configuration."""
    host = request.url.hostname or "127.0.0.1"
    port = request.url.port or 8000
    cross_host = "localhost" if host == "127.0.0.1" else "127.0.0.1"
    cross_script_url = f"http://{cross_host}:{port}/demo/assets/helper.js"

    html = f"""<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <title>Demo Storefront (Weak Security Config)</title>
  <script src="{cross_script_url}"></script>
</head>
<body>
  <main style="font-family: sans-serif; max-width: 720px; margin: 2rem auto;">
    <h1>Demo Portal — Weak Configuration Sample</h1>
    <p>หน้านี้เป็น Sandbox จำลองสำหรับการตรวจ Security Config แบบ Passive (ไม่มีข้อมูลจริง)</p>

    <form action="http://example.invalid/demo-submit" method="post">
      <label>Username: <input type="text" name="username"></label><br><br>
      <label>Password: <input type="password" name="password"></label><br><br>
      <button type="submit">Demo Login</button>
    </form>

    <p>
      <a href="https://owasp.org" target="_blank">External Link Without noopener</a>
    </p>
    <iframe src="/demo/embed" width="300" height="60" title="Demo Frame"></iframe>
  </main>
  <script>
    window.__inlineConfigDemo = true;
  </script>
</body>
</html>"""

    response = HTMLResponse(content=html)
    # Intentionally weak headers/cookies for educational passive audit demonstration
    response.headers["Server"] = "DemoServer/0.9-dev"
    response.headers["X-Powered-By"] = "LegacyPrototypeFramework/1.2"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Cache-Control"] = "public, max-age=3600"
    response.set_cookie(
        key="demo_session",
        value="demo-placeholder-not-secret",
        httponly=False,
        secure=False,
        samesite=None,
        path="/demo",
    )
    return response


@router.get("/hardened", response_class=HTMLResponse)
async def demo_hardened(request: Request) -> HTMLResponse:
    """Serve a safe local demo page illustrating strong defensive configuration."""
    html = """<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <title>Demo Portal (Hardened Security Config)</title>
  <script src="/demo/assets/helper.js"></script>
</head>
<body>
  <main style="font-family: sans-serif; max-width: 720px; margin: 2rem auto;">
    <h1>Demo Portal — Hardened Configuration Sample</h1>
    <p>หน้านี้เป็น Sandbox ที่ตั้งค่า Security Headers และแนวทางป้องกันตาม OWASP ครบถ้วน</p>

    <form action="/demo/hardened" method="post">
      <input type="hidden" name="csrf_token" value="demo-anti-csrf-placeholder">
      <label>Username: <input type="text" name="username" autocomplete="username"></label><br><br>
      <label>Password: <input type="password" name="password" autocomplete="current-password"></label><br><br>
      <button type="submit">Demo Login</button>
    </form>

    <p>
      <a href="https://owasp.org" target="_blank" rel="noopener noreferrer">External Link With noopener noreferrer</a>
    </p>
  </main>
</body>
</html>"""

    response = HTMLResponse(content=html)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    # Note: Secure flag omitted only when served over plain local HTTP so browser accepts the demo cookie,
    # or set conditionally if request scheme is https.
    is_https = request.url.scheme == "https"
    response.set_cookie(
        key="demo_hardened_sid",
        value="demo-hardened-placeholder",
        httponly=True,
        secure=is_https,
        samesite="strict",
        path="/demo",
    )
    return response
