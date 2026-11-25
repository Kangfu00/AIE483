"""Read-only passive reconnaissance using httpx and Playwright."""

from __future__ import annotations

import asyncio
import os
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from playwright.sync_api import sync_playwright

from app.config import HTTP_TIMEOUT_SECONDS, PLAYWRIGHT_TIMEOUT_MS
from app.models import (
    CookieSummary,
    FormSummary,
    LinkSummary,
    ReconSnapshot,
    ScriptSummary,
)


class _BasicHTMLMetadataParser(HTMLParser):
    """Lightweight passive HTML fallback parser when Playwright is unavailable."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.page_origin = _origin_of(base_url)
        self.title_parts: list[str] = []
        self._in_title = False
        self.scripts: list[ScriptSummary] = []
        self.forms: list[FormSummary] = []
        self.blank_links: list[LinkSummary] = []
        self.iframes_count = 0
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        if tag_l == "title":
            self._in_title = True
        elif tag_l == "script":
            src = attr_map.get("src", "").strip()
            abs_src = urljoin(self.base_url, src) if src else ""
            is_external = bool(abs_src and _origin_of(abs_src) != self.page_origin)
            self.scripts.append(
                ScriptSummary(
                    src=abs_src[:300],
                    is_inline=not bool(src),
                    is_external=is_external,
                    has_integrity=bool(attr_map.get("integrity", "").strip()),
                    crossorigin=attr_map.get("crossorigin", "").strip(),
                )
            )
        elif tag_l == "form":
            action_raw = attr_map.get("action", "").strip()
            resolved_action = urljoin(self.base_url, action_raw) if action_raw else self.base_url
            method = (attr_map.get("method", "GET") or "GET").upper()
            self._current_form = {
                "action": resolved_action[:300],
                "method": method,
                "is_insecure_action": resolved_action.lower().startswith("http://"),
                "has_password_input": False,
                "has_csrf_like_field": False,
            }
        elif tag_l == "input" and self._current_form is not None:
            input_type = attr_map.get("type", "text").lower()
            input_name = attr_map.get("name", "").lower()
            if input_type == "password":
                self._current_form["has_password_input"] = True
            if input_type == "hidden" and any(
                tok in input_name for tok in ("csrf", "xsrf", "token", "nonce")
            ):
                self._current_form["has_csrf_like_field"] = True
        elif tag_l == "a" and attr_map.get("target", "").lower() == "_blank":
            rel_tokens = {tok.lower() for tok in attr_map.get("rel", "").split()}
            self.blank_links.append(
                LinkSummary(
                    href=urljoin(self.base_url, attr_map.get("href", ""))[:300],
                    has_noopener="noopener" in rel_tokens,
                    has_noreferrer="noreferrer" in rel_tokens,
                )
            )
        elif tag_l == "iframe":
            self.iframes_count += 1

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        if tag_l == "title":
            self._in_title = False
        elif tag_l == "form" and self._current_form is not None:
            self.forms.append(FormSummary(**self._current_form))
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)


def _origin_of(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _find_cached_chromium_executable() -> str | None:
    """Locate a cached Playwright Chromium executable if default revision is absent."""
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if not local_app_data:
        return None
    cache_root = Path(local_app_data) / "ms-playwright"
    if not cache_root.exists():
        return None

    patterns = [
        "chromium_headless_shell-*/chrome-headless-shell-win64/chrome-headless-shell.exe",
        "chromium-*/chrome-win64/chrome.exe",
        "chromium-*/chrome-win/chrome.exe",
    ]
    for pattern in patterns:
        matches = sorted(cache_root.glob(pattern), reverse=True)
        for match in matches:
            if match.is_file():
                return str(match)
    return None


def _launch_chromium(playwright_obj: Any) -> tuple[Any, str]:
    """Launch headless Chromium with safe cross-environment fallbacks."""
    last_error: Exception | None = None

    # 1. Standard Playwright managed Chromium
    try:
        return playwright_obj.chromium.launch(headless=True), "playwright-chromium"
    except Exception as exc:  # noqa: BLE001
        last_error = exc

    # 2. Cached ms-playwright Chromium binary on Windows
    cached_exe = _find_cached_chromium_executable()
    if cached_exe:
        try:
            return (
                playwright_obj.chromium.launch(headless=True, executable_path=cached_exe),
                "playwright-cached-chromium",
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc

    # 3. Installed system browsers via Playwright channels
    for channel in ("chrome", "msedge"):
        try:
            return playwright_obj.chromium.launch(headless=True, channel=channel), f"playwright-{channel}"
        except Exception as exc:  # noqa: BLE001
            last_error = exc

    raise RuntimeError(f"ไม่สามารถเปิด Chromium/Edge สำหรับ Playwright ได้: {last_error}")


def _run_playwright_inspection_sync(target_url: str) -> dict[str, Any]:
    """Perform read-only Playwright DOM, cookie, and network observation."""
    observed_mixed: list[str] = []
    third_party_domains: set[str] = set()
    observed_cors: dict[str, str] = {}

    with sync_playwright() as p:
        browser, engine_label = _launch_chromium(p)
        context = browser.new_context(ignore_https_errors=False)
        page = context.new_page()
        page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)

        target_host = (urlparse(target_url).hostname or "").lower()
        target_is_https = urlparse(target_url).scheme.lower() == "https"

        def on_response(resp: Any) -> None:
            try:
                req_url = resp.url
                parsed_req = urlparse(req_url)
                req_host = (parsed_req.hostname or "").lower()
                if req_host and req_host != target_host:
                    third_party_domains.add(req_host)
                if target_is_https and parsed_req.scheme.lower() == "http":
                    if len(observed_mixed) < 25:
                        observed_mixed.append(req_url[:300])
                headers = resp.headers or {}
                for cors_key in (
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "access-control-allow-methods",
                ):
                    if cors_key in headers and cors_key not in observed_cors:
                        observed_cors[cors_key] = str(headers[cors_key])[:200]
            except Exception:  # noqa: BLE001
                return

        page.on("response", on_response)

        try:
            page.goto(target_url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_TIMEOUT_MS)
            page.wait_for_timeout(450)
            final_url = page.url

            dom_data = page.evaluate(
                """() => {
                  const pageOrigin = window.location.origin;
                  const scripts = Array.from(document.querySelectorAll('script')).map(el => {
                    const src = el.getAttribute('src') || '';
                    let absSrc = '';
                    let isExternal = false;
                    if (src) {
                      try {
                        const u = new URL(src, window.location.href);
                        absSrc = u.href;
                        isExternal = u.origin !== pageOrigin;
                      } catch {
                        absSrc = src;
                      }
                    }
                    return {
                      src: absSrc.slice(0, 300),
                      is_inline: !src,
                      is_external: isExternal,
                      has_integrity: Boolean(el.getAttribute('integrity')),
                      crossorigin: (el.getAttribute('crossorigin') || '').slice(0, 40),
                    };
                  });

                  const forms = Array.from(document.querySelectorAll('form')).map(form => {
                    const actionRaw = form.getAttribute('action') || '';
                    let resolvedAction = window.location.href;
                    if (actionRaw) {
                      try {
                        resolvedAction = new URL(actionRaw, window.location.href).href;
                      } catch {
                        resolvedAction = actionRaw;
                      }
                    }
                    const method = (form.getAttribute('method') || 'GET').toUpperCase();
                    const hasPassword = Boolean(form.querySelector('input[type="password"]'));
                    const hiddenInputs = Array.from(form.querySelectorAll('input[type="hidden"]'));
                    const hasCsrfLike = hiddenInputs.some(inp => {
                      const n = ((inp.getAttribute('name') || '') + ' ' + (inp.getAttribute('id') || '')).toLowerCase();
                      return n.includes('csrf') || n.includes('xsrf') || n.includes('token') || n.includes('nonce');
                    });
                    return {
                      action: resolvedAction.slice(0, 300),
                      method,
                      is_insecure_action: resolvedAction.toLowerCase().startsWith('http://'),
                      has_password_input: hasPassword,
                      has_csrf_like_field: hasCsrfLike,
                    };
                  });

                  const blankLinks = Array.from(document.querySelectorAll('a[target="_blank"]')).map(a => {
                    const rel = (a.getAttribute('rel') || '').toLowerCase().split(/\\s+/).filter(Boolean);
                    return {
                      href: (a.href || a.getAttribute('href') || '').slice(0, 300),
                      has_noopener: rel.includes('noopener'),
                      has_noreferrer: rel.includes('noreferrer'),
                    };
                  });

                  return {
                    title: (document.title || '').slice(0, 200),
                    scripts: scripts.slice(0, 60),
                    forms: forms.slice(0, 30),
                    blank_links: blankLinks.slice(0, 50),
                    iframes_count: document.querySelectorAll('iframe').length,
                  };
                }"""
            )

            raw_cookies = context.cookies()
            cookies = [
                CookieSummary(
                    name=str(c.get("name", ""))[:100],
                    domain=str(c.get("domain", ""))[:150],
                    path=str(c.get("path", "/"))[:150],
                    http_only=bool(c.get("httpOnly", False)),
                    secure=bool(c.get("secure", False)),
                    same_site=str(c.get("sameSite", "")),
                )
                for c in raw_cookies[:50]
            ]

            return {
                "engine": engine_label,
                "final_url": final_url,
                "cookies": cookies,
                "mixed_content_urls": observed_mixed,
                "third_party_domains": sorted(third_party_domains)[:40],
                "observed_cors_headers": observed_cors,
                **dom_data,
            }
        finally:
            context.close()
            browser.close()


async def _probe_http_redirect_to_https(client: httpx.AsyncClient, final_url: str) -> bool | None:
    """Check whether plain HTTP redirects to HTTPS for standard HTTPS targets."""
    parsed = urlparse(final_url)
    if parsed.scheme.lower() != "https":
        return None
    if parsed.port not in (None, 443):
        return None

    http_url = f"http://{parsed.hostname}{parsed.path or '/'}"
    try:
        resp = await client.get(http_url, follow_redirects=True, timeout=5.0)
        return str(resp.url).lower().startswith("https://")
    except Exception:  # noqa: BLE001
        return None


async def _probe_well_known(client: httpx.AsyncClient, base_url: str, path: str) -> int | None:
    """Safely fetch status code of standard public metadata file."""
    parsed = urlparse(base_url)
    target = f"{parsed.scheme}://{parsed.netloc}{path}"
    try:
        resp = await client.get(target, follow_redirects=True, timeout=5.0)
        return resp.status_code
    except Exception:  # noqa: BLE001
        return None


async def run_passive_recon(
    target_url: str,
    transport: httpx.AsyncBaseTransport | None = None,
    use_playwright: bool = True,
) -> ReconSnapshot:
    """Collect read-only HTTP, header, cookie, and DOM telemetry for a target URL."""
    started = time.perf_counter()

    client_kwargs: dict[str, Any] = {
        "follow_redirects": True,
        "timeout": HTTP_TIMEOUT_SECONDS,
        "headers": {"User-Agent": "AIE483-PassiveSecurityAuditor/1.0"},
    }
    if transport is not None:
        client_kwargs["transport"] = transport

    async with httpx.AsyncClient(**client_kwargs) as client:
        resp = await client.get(target_url)
        final_url = str(resp.url)
        redirect_chain = [str(r.url) for r in resp.history] + [final_url]
        lowered_headers = {k.lower(): v for k, v in resp.headers.items()}
        set_cookie_count = len(resp.headers.get_list("set-cookie"))
        html_body = resp.text if "html" in lowered_headers.get("content-type", "").lower() else ""

        http_redirects_to_https, security_txt_status, robots_txt_status = await asyncio.gather(
            _probe_http_redirect_to_https(client, final_url),
            _probe_well_known(client, final_url, "/.well-known/security.txt"),
            _probe_well_known(client, final_url, "/robots.txt"),
        )

    observed_cors: dict[str, str] = {}
    for cors_key in (
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
    ):
        if cors_key in lowered_headers:
            observed_cors[cors_key] = lowered_headers[cors_key][:200]

    pw_used = False
    pw_note: str | None = None
    pw_data: dict[str, Any] | None = None

    if use_playwright and transport is None:
        try:
            pw_data = await asyncio.to_thread(_run_playwright_inspection_sync, final_url)
            pw_used = True
            pw_note = f"Inspected via {pw_data.get('engine', 'playwright')}"
        except Exception as exc:  # noqa: BLE001
            pw_used = False
            pw_note = f"Playwright unavailable ({type(exc).__name__}); used HTTP/HTML fallback"

    if pw_data is not None:
        title = pw_data.get("title", "")
        scripts = [ScriptSummary(**s) for s in pw_data.get("scripts", [])]
        forms = [FormSummary(**f) for f in pw_data.get("forms", [])]
        blank_links = [LinkSummary(**lnk) for lnk in pw_data.get("blank_links", [])]
        iframes_count = int(pw_data.get("iframes_count", 0))
        cookies = pw_data.get("cookies", [])
        mixed_content_urls = pw_data.get("mixed_content_urls", [])
        third_party_domains = pw_data.get("third_party_domains", [])
        for k, v in pw_data.get("observed_cors_headers", {}).items():
            observed_cors.setdefault(k, v)
    else:
        parser = _BasicHTMLMetadataParser(final_url)
        if html_body:
            parser.feed(html_body[:250_000])
        title = "".join(parser.title_parts).strip()[:200]
        scripts = parser.scripts
        forms = parser.forms
        blank_links = parser.blank_links
        iframes_count = parser.iframes_count
        cookies = _parse_set_cookie_metadata(resp.headers.get_list("set-cookie"))
        mixed_content_urls = []
        third_party_domains = []

    parsed_final = urlparse(final_url)
    elapsed_ms = int((time.perf_counter() - started) * 1000)

    return ReconSnapshot(
        target_url=target_url,
        final_url=final_url,
        scheme=parsed_final.scheme.lower(),
        status_code=resp.status_code,
        redirect_chain=redirect_chain,
        is_https=parsed_final.scheme.lower() == "https",
        http_redirects_to_https=http_redirects_to_https,
        response_headers=lowered_headers,
        set_cookie_count=set_cookie_count,
        cookies=cookies,
        title=title,
        scripts=scripts,
        forms=forms,
        blank_links=blank_links,
        iframes_count=iframes_count,
        mixed_content_urls=mixed_content_urls,
        third_party_domains=third_party_domains,
        observed_cors_headers=observed_cors,
        security_txt_status=security_txt_status,
        robots_txt_status=robots_txt_status,
        playwright_used=pw_used,
        playwright_note=pw_note,
        recon_duration_ms=elapsed_ms,
    )


def _parse_set_cookie_metadata(raw_headers: list[str]) -> list[CookieSummary]:
    """Extract non-sensitive cookie flags from Set-Cookie response headers."""
    items: list[CookieSummary] = []
    for raw in raw_headers[:50]:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()[:100]
        attrs = {p.lower(): p for p in parts[1:]}
        same_site = ""
        path = "/"
        domain = ""
        for lower_part, orig_part in attrs.items():
            if lower_part.startswith("samesite="):
                same_site = orig_part.split("=", 1)[1].strip()
            elif lower_part.startswith("path="):
                path = orig_part.split("=", 1)[1].strip()
            elif lower_part.startswith("domain="):
                domain = orig_part.split("=", 1)[1].strip()
        items.append(
            CookieSummary(
                name=name,
                domain=domain,
                path=path,
                http_only="httponly" in attrs,
                secure="secure" in attrs,
                same_site=same_site,
            )
        )
    return items
