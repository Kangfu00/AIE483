"""Strictly passive, read-only tools invocable by the AI security agent."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlparse

import httpx

from app.config import normalize_and_validate_url
from app.models import ReconSnapshot


@dataclass
class ToolContext:
    """Execution context scoped to a single passive audit session."""

    snapshot: ReconSnapshot
    transport: httpx.AsyncBaseTransport | None = None
    subpage_inspections_used: int = 0


@dataclass(frozen=True)
class PassiveToolSpec:
    """Metadata, JSON parameter schema, and handler for one passive tool."""

    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[[dict[str, Any], ToolContext], Awaitable[tuple[str, dict[str, Any]]]]


def _inspect_tls_sync(hostname: str, port: int) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=5.0) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert() or {}
            protocol = ssock.version() or ""
            cipher = ssock.cipher()

    subject_dict = {k: v for item in cert.get("subject", ()) for k, v in item}
    issuer_dict = {k: v for item in cert.get("issuer", ()) for k, v in item}
    not_after_raw = str(cert.get("notAfter", ""))
    days_remaining: int | None = None
    if not_after_raw:
        try:
            expiry = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            days_remaining = None

    return {
        "tls_enabled": True,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else "",
        "subject_cn": subject_dict.get("commonName", ""),
        "issuer_org": issuer_dict.get("organizationName", issuer_dict.get("commonName", "")),
        "not_after": not_after_raw,
        "days_remaining": days_remaining,
    }


async def _tool_inspect_tls(args: dict[str, Any], ctx: ToolContext) -> tuple[str, dict[str, Any]]:
    snap = ctx.snapshot
    if not snap.is_https:
        return (
            "เป้าหมายใช้ HTTP แบบไม่เข้ารหัส จึงไม่มี TLS Certificate",
            {"tls_enabled": False, "scheme": snap.scheme},
        )

    parsed = urlparse(snap.final_url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    try:
        info = await asyncio.to_thread(_inspect_tls_sync, host, port)
        days = info.get("days_remaining")
        days_txt = f"เหลืออายุ {days} วัน" if days is not None else "ไม่ทราบวันหมดอายุ"
        summary = f"เชื่อมต่อด้วย {info['protocol']} ({info['issuer_org'] or 'CA'}), {days_txt}"
        return summary, info
    except Exception as exc:  # noqa: BLE001
        return (
            f"ไม่สามารถตรวจสอบ TLS Certificate ได้ ({type(exc).__name__})",
            {"tls_enabled": True, "error": type(exc).__name__},
        )


async def _tool_parse_csp(args: dict[str, Any], ctx: ToolContext) -> tuple[str, dict[str, Any]]:
    csp = ctx.snapshot.response_headers.get("content-security-policy", "").strip()
    if not csp:
        return (
            "ไม่พบ Content-Security-Policy Header บนหน้านี้",
            {"present": False, "directives": {}, "warnings": ["missing_csp"]},
        )

    directives: dict[str, list[str]] = {}
    for raw_part in csp.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        directives[name] = tokens[1:]

    warnings: list[str] = []
    script_src = directives.get("script-src") or directives.get("default-src") or []
    if "'unsafe-inline'" in script_src:
        warnings.append("unsafe_inline_in_script_src")
    if "'unsafe-eval'" in script_src:
        warnings.append("unsafe_eval_in_script_src")
    if "*" in script_src:
        warnings.append("wildcard_in_script_src")
    if "frame-ancestors" not in directives:
        warnings.append("missing_frame_ancestors")
    if "object-src" not in directives:
        warnings.append("missing_object_src")

    summary = (
        f"พบ {len(directives)} directives; คำเตือน: {', '.join(warnings)}"
        if warnings
        else f"พบ {len(directives)} directives และไม่พบจุดอ่อนหลักใน script-src / frame-ancestors"
    )
    return summary, {
        "present": True,
        "directive_count": len(directives),
        "directive_names": list(directives.keys())[:15],
        "script_src": script_src[:12],
        "frame_ancestors": directives.get("frame-ancestors", []),
        "warnings": warnings,
    }


def _is_ip_or_local(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _doh_lookup(client: httpx.AsyncClient, name: str, qtype: str) -> list[str]:
    resp = await client.get(
        "https://dns.google/resolve",
        params={"name": name, "type": qtype},
        timeout=5.0,
    )
    resp.raise_for_status()
    data = resp.json()
    return [str(ans.get("data", "")).strip('"') for ans in data.get("Answer", []) if ans.get("data")]


async def _tool_check_dns(args: dict[str, Any], ctx: ToolContext) -> tuple[str, dict[str, Any]]:
    host = (urlparse(ctx.snapshot.final_url).hostname or "").lower()
    if not host or _is_ip_or_local(host):
        return (
            "ข้ามการตรวจ DNS สาธารณะเนื่องจากเป้าหมายเป็น localhost หรือ IP ภายใน",
            {"skipped": True, "host": host},
        )

    parts = host.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            caa_task = _doh_lookup(client, host, "CAA")
            txt_task = _doh_lookup(client, base_domain, "TXT")
            dmarc_task = _doh_lookup(client, f"_dmarc.{base_domain}", "TXT")
            caa, txt_records, dmarc_records = await asyncio.gather(
                caa_task,
                txt_task,
                dmarc_task,
                return_exceptions=True,
            )

        caa_list = caa if isinstance(caa, list) else []
        txt_list = txt_records if isinstance(txt_records, list) else []
        dmarc_list = dmarc_records if isinstance(dmarc_records, list) else []

        has_spf = any("v=spf1" in t.lower() for t in txt_list)
        has_dmarc = any("v=dmarc1" in d.lower() for d in dmarc_list)

        summary = (
            f"โดเมน {base_domain}: CAA={len(caa_list)} records, SPF={'มี' if has_spf else 'ไม่พบ'}, "
            f"DMARC={'มี' if has_dmarc else 'ไม่พบ'}"
        )
        return summary, {
            "skipped": False,
            "domain": base_domain,
            "caa_records": caa_list[:5],
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
        }
    except Exception as exc:  # noqa: BLE001
        return (
            f"ไม่สามารถสอบถาม DNS record ได้ ({type(exc).__name__})",
            {"skipped": False, "error": type(exc).__name__},
        )


async def _tool_inspect_subpage(args: dict[str, Any], ctx: ToolContext) -> tuple[str, dict[str, Any]]:
    if ctx.subpage_inspections_used >= 2:
        return (
            "ครบโควตาการสำรวจหน้าย่อย (สูงสุด 2 หน้า) ในรอบนี้แล้ว",
            {"inspected": False, "reason": "subpage_quota_reached"},
        )

    base_url = ctx.snapshot.final_url
    base_parsed = urlparse(base_url)
    base_origin = f"{base_parsed.scheme.lower()}://{base_parsed.netloc.lower()}"

    requested = str(args.get("path_or_url") or "").strip()
    candidate = ""
    if requested:
        joined = urljoin(base_url, requested)
        try:
            validated = normalize_and_validate_url(joined)
            p = urlparse(validated)
            if f"{p.scheme.lower()}://{p.netloc.lower()}" == base_origin:
                candidate = validated
        except ValueError:
            candidate = ""
        if not candidate:
            return (
                "ปฏิเสธการเข้าถึงลิงก์ต่างโดเมน (อนุญาตเฉพาะลิงก์ภายในโดเมนเดียวกันเท่านั้น)",
                {"inspected": False, "reason": "cross_origin_blocked"},
            )

    if not candidate:
        links = ctx.snapshot.same_origin_links
        if not links:
            return (
                "ไม่พบลิงก์ภายในโดเมนเดียวกัน (same-origin) บนหน้าแรกให้สำรวจเพิ่มเติม",
                {"inspected": False, "reason": "no_same_origin_links"},
            )
        priority_keywords = ("login", "signin", "auth", "account", "admin", "register", "contact")
        prioritized = [lnk for lnk in links if any(kw in lnk.lower() for kw in priority_keywords)]
        candidate = prioritized[0] if prioritized else links[0]

    ctx.subpage_inspections_used += 1

    client_kwargs: dict[str, Any] = {
        "follow_redirects": True,
        "timeout": 6.0,
        "headers": {"User-Agent": "AIE483-PassiveSecurityAuditor/1.0"},
    }
    if ctx.transport is not None:
        client_kwargs["transport"] = ctx.transport

    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.get(candidate)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        body_lower = resp.text[:50_000].lower() if "html" in hdrs.get("content-type", "").lower() else ""
        has_form = "<form" in body_lower
        has_password = 'type="password"' in body_lower or "type='password'" in body_lower
        has_csp = "content-security-policy" in hdrs
        has_xfo = "x-frame-options" in hdrs
        cache_ctl = hdrs.get("cache-control", "")

        summary = (
            f"สำรวจหน้าย่อย {urlparse(candidate).path or '/'} (HTTP {resp.status_code}): "
            f"ฟอร์ม={'มี' if has_form else 'ไม่มี'}, CSP={'มี' if has_csp else 'ไม่มี'}"
        )
        return summary, {
            "inspected": True,
            "url": candidate,
            "status_code": resp.status_code,
            "has_form": has_form,
            "has_password_input": has_password,
            "has_csp": has_csp,
            "has_x_frame_options": has_xfo,
            "cache_control": cache_ctl[:100],
        }
    except Exception as exc:  # noqa: BLE001
        return (
            f"ไม่สามารถเปิดหน้าย่อย {candidate} ได้ ({type(exc).__name__})",
            {"inspected": False, "url": candidate, "error": type(exc).__name__},
        )


async def _tool_fetch_public_files(args: dict[str, Any], ctx: ToolContext) -> tuple[str, dict[str, Any]]:
    parsed = urlparse(ctx.snapshot.final_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    client_kwargs: dict[str, Any] = {
        "follow_redirects": True,
        "timeout": 5.0,
        "headers": {"User-Agent": "AIE483-PassiveSecurityAuditor/1.0"},
    }
    if ctx.transport is not None:
        client_kwargs["transport"] = ctx.transport

    sec_info: dict[str, Any] = {"status": ctx.snapshot.security_txt_status}
    robots_info: dict[str, Any] = {"status": ctx.snapshot.robots_txt_status}

    async with httpx.AsyncClient(**client_kwargs) as client:
        for path, bucket in (("/.well-known/security.txt", sec_info), ("/robots.txt", robots_info)):
            try:
                r = await client.get(f"{origin}{path}")
                bucket["status"] = r.status_code
                if r.status_code == 200 and "html" not in r.headers.get("content-type", "").lower():
                    lines = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
                    bucket["sample_lines"] = lines[:6]
            except Exception:  # noqa: BLE001
                continue

    sec_ok = sec_info.get("status") == 200
    rob_ok = robots_info.get("status") == 200
    summary = (
        f"security.txt={'พบ (200)' if sec_ok else sec_info.get('status')}, "
        f"robots.txt={'พบ (200)' if rob_ok else robots_info.get('status')}"
    )
    return summary, {"security_txt": sec_info, "robots_txt": robots_info}


PASSIVE_TOOLS: dict[str, PassiveToolSpec] = {
    "inspect_tls_certificate": PassiveToolSpec(
        name="inspect_tls_certificate",
        description="Inspect the HTTPS TLS protocol version, certificate issuer, and days until expiry (read-only).",
        parameters={"type": "object", "properties": {}, "required": []},
        handler=_tool_inspect_tls,
    ),
    "parse_csp_directives": PassiveToolSpec(
        name="parse_csp_directives",
        description="Parse Content-Security-Policy header directives to check script-src, unsafe-inline, and frame-ancestors.",
        parameters={"type": "object", "properties": {}, "required": []},
        handler=_tool_parse_csp,
    ),
    "check_dns_security_records": PassiveToolSpec(
        name="check_dns_security_records",
        description="Perform passive public DNS lookup for CAA, SPF, and DMARC records on the target domain.",
        parameters={"type": "object", "properties": {}, "required": []},
        handler=_tool_check_dns,
    ),
    "inspect_same_origin_subpage": PassiveToolSpec(
        name="inspect_same_origin_subpage",
        description="Safely read one same-origin link discovered on the landing page (e.g. login/contact) to check its headers and forms.",
        parameters={
            "type": "object",
            "properties": {
                "path_or_url": {
                    "type": "string",
                    "description": "Optional same-origin path or URL from same_origin_links.",
                }
            },
            "required": [],
        },
        handler=_tool_inspect_subpage,
    ),
    "fetch_public_security_files": PassiveToolSpec(
        name="fetch_public_security_files",
        description="Read /.well-known/security.txt (RFC 9116) and /robots.txt metadata.",
        parameters={"type": "object", "properties": {}, "required": []},
        handler=_tool_fetch_public_files,
    ),
}


def openai_tool_schemas() -> list[dict[str, Any]]:
    """Return OpenAI/OpenTyphoon-compatible function tool definitions."""
    return [
        {
            "type": "function",
            "function": {
                "name": spec.name,
                "description": spec.description,
                "parameters": spec.parameters,
            },
        }
        for spec in PASSIVE_TOOLS.values()
    ]


def gemini_tool_schemas() -> list[dict[str, Any]]:
    """Return Gemini functionDeclarations list."""
    return [
        {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.parameters,
        }
        for spec in PASSIVE_TOOLS.values()
    ]


async def execute_passive_tool(
    tool_name: str,
    arguments: dict[str, Any],
    ctx: ToolContext,
) -> tuple[str, dict[str, Any], int]:
    """Validate and execute one registered passive tool with timing."""
    started = time.perf_counter()
    spec = PASSIVE_TOOLS.get(tool_name)
    if spec is None:
        return (
            f"ปฏิเสธการเรียกเครื่องมือที่ไม่อยู่ในรายการที่อนุญาต: {tool_name}",
            {"allowed": False},
            0,
        )
    summary, findings = await spec.handler(arguments or {}, ctx)
    elapsed_ms = max(1, int((time.perf_counter() - started) * 1000))
    return summary, findings, elapsed_ms
