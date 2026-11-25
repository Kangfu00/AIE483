"""Modular passive (non-intrusive) security posture checks."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from app.models import CheckResult, ReconSnapshot


@dataclass(frozen=True)
class CheckDefinition:
    """Registry entry describing a single passive audit check."""

    id: str
    name: str
    category: str
    owasp_ref: str
    weight: int
    runner: Callable[[ReconSnapshot, int], CheckResult]


def _is_localhost(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def _extract_csp_directive(csp: str, directive_name: str) -> str:
    for part in csp.split(";"):
        cleaned = part.strip()
        if cleaned.lower().startswith(directive_name.lower()):
            return cleaned
    return ""


def _check_https_transport(snapshot: ReconSnapshot, order_index: int) -> CheckResult:
    started = time.perf_counter()
    headers = snapshot.response_headers
    hsts = headers.get("strict-transport-security", "")
    local_host = _is_localhost(snapshot.final_url)

    evidence: list[str] = [
        f"Final URL: {snapshot.final_url}",
        f"Scheme: {snapshot.scheme.upper()}",
    ]
    recommendations: list[str] = []

    if snapshot.http_redirects_to_https is True:
        evidence.append("HTTP -> HTTPS redirect: ทำงานถูกต้อง")
    elif snapshot.http_redirects_to_https is False:
        evidence.append("HTTP -> HTTPS redirect: ไม่พบการบังคับ redirect")

    if hsts:
        evidence.append(f"Strict-Transport-Security: {hsts}")
    else:
        evidence.append("Strict-Transport-Security: ไม่พบ Header")

    score = 100
    if not snapshot.is_https:
        if local_host:
            status = "warn"
            score = 55
            summary = "เซิร์ฟเวอร์ทำงานบน HTTP ในเครื่อง (Local/Sandbox) ซึ่งควรเปิดใช้งาน HTTPS + HSTS เมื่อขึ้น Production"
        else:
            status = "fail"
            score = 15
            summary = "เว็บไซต์ไม่ได้ให้บริการผ่าน HTTPS ทำให้ข้อมูลระหว่างทางเสี่ยงต่อการถูกดักฟังหรือแก้ไข"
        recommendations.append("ติดตั้ง TLS Certificate และบังคับ Redirect จาก HTTP (พอร์ต 80) ไปยัง HTTPS (พอร์ต 443)")
        recommendations.append("เพิ่ม Header Strict-Transport-Security (HSTS) เมื่อใช้งานบน HTTPS")
    else:
        if not hsts:
            status = "warn"
            score = 70
            summary = "เว็บใช้งาน HTTPS แล้ว แต่ยังขาด Strict-Transport-Security (HSTS) Header"
            recommendations.append("เพิ่ม Strict-Transport-Security เพื่อบังคับให้เบราว์เซอร์เชื่อมต่อผ่าน HTTPS เสมอ")
        else:
            max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            if max_age < 15_552_000:
                status = "warn"
                score = 80
                summary = "เปิดใช้ HSTS แล้ว แต่ค่า max-age ยังน้อยกว่า 6 เดือน (แนะนำอย่างน้อย 1 ปี)"
                recommendations.append("ปรับ max-age ใน HSTS เป็นอย่างน้อย 31536000 (1 ปี) และพิจารณา includeSubDomains")
            elif snapshot.http_redirects_to_https is False:
                status = "warn"
                score = 85
                summary = "HTTPS และ HSTS พร้อมใช้งาน แต่พอร์ต HTTP ไม่ได้บังคับ redirect มาที่ HTTPS"
                recommendations.append("ตั้งค่า Web Server ให้ redirect HTTP ทุก path มาที่ HTTPS (301/308)")
            else:
                status = "pass"
                score = 100
                summary = "การเข้ารหัสการสื่อสารผ่าน HTTPS และนโยบาย HSTS ตั้งค่าได้เหมาะสม"

    return CheckResult(
        check_id="https_transport",
        name="การเข้ารหัสและการส่งต่อ HTTPS / HSTS",
        category="Transport Security",
        order_index=order_index,
        status=status,
        score=score,
        summary=summary,
        evidence=evidence,
        recommendations=recommendations,
        remediation_snippet=(
            "Strict-Transport-Security: max-age=31536000; includeSubDomains"
            if status != "pass"
            else None
        ),
        owasp_ref="OWASP ASVS V9.1 / Transport Layer Protection",
        duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
    )


def _check_security_headers(snapshot: ReconSnapshot, order_index: int) -> CheckResult:
    started = time.perf_counter()
    h = snapshot.response_headers
    evidence: list[str] = []
    recommendations: list[str] = []

    csp = h.get("content-security-policy", "")
    xcto = h.get("x-content-type-options", "")
    ref_pol = h.get("referrer-policy", "")
    perm_pol = h.get("permissions-policy", "")
    coop = h.get("cross-origin-opener-policy", "")

    score = 100
    missing_core: list[str] = []
    weak_notes: list[str] = []

    if csp:
        evidence.append(f"Content-Security-Policy: {csp[:180]}")
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            weak_notes.append("CSP มีการใช้ 'unsafe-inline' หรือ 'unsafe-eval' ซึ่งลดประสิทธิภาพการป้องกัน XSS")
            score -= 15
    else:
        missing_core.append("Content-Security-Policy")
        evidence.append("Content-Security-Policy: ไม่พบ")
        score -= 35

    if xcto.lower() == "nosniff":
        evidence.append("X-Content-Type-Options: nosniff")
    else:
        missing_core.append("X-Content-Type-Options")
        evidence.append(f"X-Content-Type-Options: {xcto or 'ไม่พบ'}")
        score -= 20

    if ref_pol:
        evidence.append(f"Referrer-Policy: {ref_pol}")
    else:
        missing_core.append("Referrer-Policy")
        evidence.append("Referrer-Policy: ไม่พบ")
        score -= 15

    if perm_pol:
        evidence.append(f"Permissions-Policy: {perm_pol[:150]}")
    else:
        evidence.append("Permissions-Policy: ไม่พบ (แนะนำให้เพิ่ม)")
        score -= 10

    if coop:
        evidence.append(f"Cross-Origin-Opener-Policy: {coop}")
    else:
        evidence.append("Cross-Origin-Opener-Policy: ไม่พบ (แนะนำให้เพิ่ม)")
        score -= 5

    score = max(0, score)

    if len(missing_core) >= 2:
        status = "fail"
        summary = f"ขาด Security Headers สำคัญหลายรายการ ({', '.join(missing_core)})"
    elif missing_core or weak_notes:
        status = "warn"
        summary = "มี Security Headers พื้นฐานบางส่วน แต่ยังมีจุดที่ควรเสริมความแข็งแกร่ง"
    else:
        status = "pass"
        summary = "Security Headers หลักตามมาตรฐาน OWASP ถูกตั้งค่าไว้อย่างครบถ้วน"

    if "Content-Security-Policy" in missing_core:
        recommendations.append("กำหนด Content-Security-Policy (CSP) เพื่อควบคุมแหล่งที่มาของ Script, Style และ Resource ที่อนุญาต")
    if weak_notes:
        recommendations.extend(weak_notes)
    if "X-Content-Type-Options" in missing_core:
        recommendations.append("เพิ่ม X-Content-Type-Options: nosniff เพื่อป้องกัน MIME-type sniffing")
    if "Referrer-Policy" in missing_core:
        recommendations.append("เพิ่ม Referrer-Policy: strict-origin-when-cross-origin เพื่อจำกัดการส่ง URL ต้นทางข้ามโดเมน")
    if not perm_pol:
        recommendations.append("เพิ่ม Permissions-Policy เพื่อปิด API ที่ไม่จำเป็น เช่น camera, microphone, geolocation")

    snippet = (
        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'\n"
        "X-Content-Type-Options: nosniff\n"
        "Referrer-Policy: strict-origin-when-cross-origin\n"
        "Permissions-Policy: geolocation=(), microphone=(), camera=()"
    )

    return CheckResult(
        check_id="security_headers",
        name="HTTP Security Headers ตามมาตรฐาน OWASP",
        category="HTTP Headers",
        order_index=order_index,
        status=status,
        score=score,
        summary=summary,
        evidence=evidence,
        recommendations=recommendations,
        remediation_snippet=snippet if status != "pass" else None,
        owasp_ref="OWASP Secure Headers Project",
        duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
    )


def _check_clickjacking_defense(snapshot: ReconSnapshot, order_index: int) -> CheckResult:
    started = time.perf_counter()
    h = snapshot.response_headers
    xfo = h.get("x-frame-options", "")
    csp = h.get("content-security-policy", "")
    frame_ancestors = _extract_csp_directive(csp, "frame-ancestors")

    evidence = [
        f"X-Frame-Options: {xfo or 'ไม่พบ'}",
        f"CSP frame-ancestors: {frame_ancestors or 'ไม่พบ'}",
        f"จำนวน <iframe> ที่พบบนหน้าเว็บ: {snapshot.iframes_count}",
    ]
    recommendations: list[str] = []

    has_xfo = xfo.upper() in {"DENY", "SAMEORIGIN"}
    has_fa = bool(frame_ancestors)

    if has_fa and has_xfo:
        status = "pass"
        score = 100
        summary = "มีการป้องกัน Clickjacking ทั้งผ่าน CSP frame-ancestors และ X-Frame-Options"
    elif has_fa or has_xfo:
        status = "warn"
        score = 80
        summary = "มีการป้องกัน Clickjacking แล้วหนึ่งชั้น แต่ควรใส่ทั้ง frame-ancestors และ X-Frame-Options เพื่อรองรับเบราว์เซอร์ทุกรุ่น"
        if not has_fa:
            recommendations.append("เพิ่ม directive frame-ancestors 'none' (หรือ 'self') ใน Content-Security-Policy")
        if not has_xfo:
            recommendations.append("เพิ่ม X-Frame-Options: DENY หรือ SAMEORIGIN ควบคู่กัน")
    else:
        status = "fail"
        score = 20
        summary = "ไม่พบการป้องกัน Clickjacking ทำให้หน้าเว็บอาจถูกฝังใน <iframe> จากเว็บภายนอกได้"
        recommendations.append("เพิ่ม Content-Security-Policy: frame-ancestors 'none' และ X-Frame-Options: DENY")

    return CheckResult(
        check_id="clickjacking_defense",
        name="การป้องกัน Clickjacking และ Framing",
        category="Browser Isolation",
        order_index=order_index,
        status=status,
        score=score,
        summary=summary,
        evidence=evidence,
        recommendations=recommendations,
        remediation_snippet=(
            "X-Frame-Options: DENY\nContent-Security-Policy: frame-ancestors 'none'"
            if status != "pass"
            else None
        ),
        owasp_ref="OWASP Clickjacking Defense Cheat Sheet",
        duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
    )


def _check_cookie_hygiene(snapshot: ReconSnapshot, order_index: int) -> CheckResult:
    started = time.perf_counter()
    cookies = snapshot.cookies
    evidence: list[str] = [f"จำนวน Cookie ที่สังเกตพบ: {len(cookies)} (Set-Cookie headers: {snapshot.set_cookie_count})"]
    recommendations: list[str] = []

    if not cookies:
        return CheckResult(
            check_id="cookie_hygiene",
            name="ความปลอดภัยของ Cookie และ Session Flags",
            category="Session Hygiene",
            order_index=order_index,
            status="info",
            score=90,
            summary="ไม่พบการตั้งค่า Cookie ในการโหลดหน้าเว็บครั้งแรก (อาจสร้าง Cookie หลัง Login หรือไม่มีการใช้งาน Cookie)",
            evidence=evidence,
            recommendations=["หากมี Cookie สำหรับ Session หลังเข้าสู่ระบบ ควรตรวจสอบให้ตั้งค่า HttpOnly, Secure และ SameSite=Lax/Strict เสมอ"],
            remediation_snippet=None,
            owasp_ref="OWASP Session Management Cheat Sheet",
            duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
        )

    issues = 0
    local_http = _is_localhost(snapshot.final_url) and not snapshot.is_https
    for c in cookies:
        missing: list[str] = []
        if not c.http_only:
            missing.append("HttpOnly")
        if not c.secure and not local_http:
            missing.append("Secure")
        if not c.same_site or c.same_site.lower() == "none":
            if not c.same_site:
                missing.append("SameSite")
            elif not c.secure:
                missing.append("Secure (required for SameSite=None)")

        status_txt = f"ขาด {', '.join(missing)}" if missing else "ตั้งค่า Flag สำคัญครบ"
        if missing:
            issues += 1
        elif local_http and not c.secure:
            status_txt += " (หมายเหตุ: บน HTTP localhost ยังไม่เปิด Secure)"

        evidence.append(
            f"Cookie '{c.name}' (path={c.path}): HttpOnly={c.http_only}, Secure={c.secure}, SameSite={c.same_site or 'unset'} -> {status_txt}"
        )

    if issues == 0:
        status = "warn" if local_http else "pass"
        score = 88 if local_http else 100
        summary = (
            "Cookie ตั้งค่า HttpOnly/SameSite ดีแล้ว (ควรเปิด Secure เพิ่มเมื่อขึ้น HTTPS Production)"
            if local_http
            else "Cookie ทั้งหมดที่พบมีการตั้งค่า Flag ความปลอดภัยอย่างเหมาะสม"
        )
    elif issues == len(cookies):
        status = "fail"
        score = 25
        summary = "Cookie ที่พบขาด Security Flags สำคัญ (เช่น HttpOnly / Secure / SameSite)"
    else:
        status = "warn"
        score = 60
        summary = f"พบ Cookie {issues}/{len(cookies)} รายการที่ยังขาด Security Flags บางตัว"

    if issues > 0:
        recommendations.append("ตั้งค่า HttpOnly เพื่อป้องกัน JavaScript เข้าถึง Session Cookie")
        recommendations.append("ตั้งค่า Secure เพื่อส่ง Cookie เฉพาะบนการเชื่อมต่อ HTTPS")
        recommendations.append("กำหนด SameSite=Lax หรือ SameSite=Strict เพื่อลดความเสี่ยง CSRF")

    return CheckResult(
        check_id="cookie_hygiene",
        name="ความปลอดภัยของ Cookie และ Session Flags",
        category="Session Hygiene",
        order_index=order_index,
        status=status,
        score=score,
        summary=summary,
        evidence=evidence,
        recommendations=recommendations,
        remediation_snippet=(
            "Set-Cookie: session_id=...; Path=/; HttpOnly; Secure; SameSite=Lax"
            if issues > 0
            else None
        ),
        owasp_ref="OWASP Session Management Cheat Sheet",
        duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
    )


def _check_mixed_content_sri(snapshot: ReconSnapshot, order_index: int) -> CheckResult:
    started = time.perf_counter()
    external_scripts = [s for s in snapshot.scripts if s.is_external]
    missing_sri = [s for s in external_scripts if not s.has_integrity]
    inline_scripts = [s for s in snapshot.scripts if s.is_inline]
    mixed = snapshot.mixed_content_urls

    evidence = [
        f"Playwright ตรวจทรัพยากร Mixed Content (HTTP บน HTTPS): {len(mixed)} รายการ",
        f"สคริปต์ทั้งหมด: {len(snapshot.scripts)} (ภายนอก {len(external_scripts)}, inline {len(inline_scripts)})",
        f"สคริปต์ภายนอกที่ไม่มี Subresource Integrity (integrity): {len(missing_sri)} รายการ",
    ]
    for url in mixed[:5]:
        evidence.append(f"Mixed Content URL: {url}")
    for sc in missing_sri[:5]:
        evidence.append(f"External Script ไม่มี SRI: {sc.src}")

    recommendations: list[str] = []
    score = 100

    if mixed:
        score -= 45
        recommendations.append("เปลี่ยนลิงก์ทรัพยากร (script/img/css) ทั้งหมดให้โหลดผ่าน HTTPS เพื่อกำจัด Mixed Content")
    if missing_sri:
        score -= min(35, 15 + 5 * len(missing_sri))
        recommendations.append("เพิ่ม attribute integrity และ crossorigin=\"anonymous\" (SRI) ให้กับ <script> ที่โหลดจากโดเมนภายนอก")

    score = max(0, score)
    if mixed:
        status = "fail"
        summary = "พบ Mixed Content (โหลดทรัพยากรผ่าน HTTP บนหน้า HTTPS) และ/หรือขาด SRI สำหรับสคริปต์ภายนอก"
    elif missing_sri:
        status = "warn"
        summary = f"พบสคริปต์ภายนอก {len(missing_sri)} รายการที่ยังไม่ได้ใส่ Subresource Integrity (SRI)"
    else:
        status = "pass"
        summary = "ไม่พบ Mixed Content และสคริปต์ภายนอกมี Subresource Integrity (หรือไม่มีสคริปต์ภายนอก)"

    return CheckResult(
        check_id="mixed_content_sri",
        name="Mixed Content และ Subresource Integrity (SRI)",
        category="Supply Chain & Integrity",
        order_index=order_index,
        status=status,
        score=score,
        summary=summary,
        evidence=evidence,
        recommendations=recommendations,
        remediation_snippet=(
            '<script src="https://cdn.example.com/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>'
            if missing_sri
            else None
        ),
        owasp_ref="OWASP A08:2021 Software and Data Integrity Failures",
        duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
    )


def _check_form_client_hygiene(snapshot: ReconSnapshot, order_index: int) -> CheckResult:
    started = time.perf_counter()
    forms = snapshot.forms
    blank_links = snapshot.blank_links
    insecure_forms = [f for f in forms if f.is_insecure_action]
    password_forms = [f for f in forms if f.has_password_input]
    post_without_csrf_hint = [
        f for f in forms if f.method.upper() == "POST" and not f.has_csrf_like_field
    ]
    unsafe_blank_links = [lnk for lnk in blank_links if not (lnk.has_noopener or lnk.has_noreferrer)]

    local_host = _is_localhost(snapshot.final_url)
    evidence = [
        f"ฟอร์มที่พบบนหน้าเว็บ: {len(forms)} (มีช่อง Password: {len(password_forms)})",
        f"ฟอร์มที่ส่งข้อมูลผ่าน action http:// : {len(insecure_forms)}",
        f"ลิงก์ target=\"_blank\" ที่ขาด rel=\"noopener noreferrer\": {len(unsafe_blank_links)} / {len(blank_links)}",
    ]
    for f in insecure_forms[:4]:
        evidence.append(f"Insecure form action: [{f.method}] {f.action}")

    recommendations: list[str] = []
    score = 100

    # External non-localhost insecure form action is always high risk
    non_local_insecure = [
        f for f in insecure_forms if not _is_localhost(f.action)
    ]
    if non_local_insecure:
        score -= 50
        recommendations.append("เปลี่ยน action ของฟอร์มให้ส่งข้อมูลผ่าน HTTPS เท่านั้น")
    elif insecure_forms and not local_host:
        score -= 45
        recommendations.append("เปลี่ยน action ของฟอร์มให้ส่งข้อมูลผ่าน HTTPS เท่านั้น")
    elif password_forms and not snapshot.is_https:
        score -= 15 if local_host else 50
        recommendations.append("หน้าเว็บที่มีฟอร์มกรอกรหัสผ่านต้องให้บริการผ่าน HTTPS เท่านั้นเมื่อขึ้น Production")

    if post_without_csrf_hint:
        score -= 15
        recommendations.append("ตรวจสอบให้แน่ใจว่าฟอร์ม POST มีกลไกป้องกัน CSRF (เช่น Anti-CSRF token หรือ SameSite cookie)")

    if unsafe_blank_links:
        score -= 10
        recommendations.append('เพิ่ม rel="noopener noreferrer" ให้กับลิงก์ <a target="_blank"> ทุกจุด')

    score = max(0, score)
    if non_local_insecure or (password_forms and not snapshot.is_https and not local_host):
        status = "fail"
        summary = "พบฟอร์มที่ส่งข้อมูลหรือรับรหัสผ่านผ่านช่องทางที่ไม่เข้ารหัส (HTTP)"
    elif post_without_csrf_hint or unsafe_blank_links or (insecure_forms and not local_host):
        status = "warn"
        summary = "พบจุดที่ควรปรับปรุงด้านความปลอดภัยของฟอร์มหรือแท็บลิงก์ฝั่ง Client"
    elif local_host and (insecure_forms or (password_forms and not snapshot.is_https)):
        status = "warn"
        summary = "ฟอร์มตั้งค่า Anti-CSRF และลิงก์ได้เหมาะสมแล้ว (ทำงานบน HTTP localhost — ควรใช้ HTTPS เมื่อขึ้น Production)"
    else:
        status = "pass"
        summary = "การตั้งค่าฟอร์มและลิงก์เปิดแท็บใหม่ฝั่ง Client อยู่ในเกณฑ์ปลอดภัย"

    return CheckResult(
        check_id="form_client_hygiene",
        name="ความปลอดภัยของฟอร์มและลิงก์ฝั่ง Client (DOM)",
        category="Client-Side Hygiene",
        order_index=order_index,
        status=status,
        score=score,
        summary=summary,
        evidence=evidence,
        recommendations=recommendations,
        remediation_snippet=(
            '<form action="https://yourdomain.com/login" method="post">\n'
            '  <input type="hidden" name="csrf_token" value="...">\n'
            '</form>\n'
            '<a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>'
            if status != "pass"
            else None
        ),
        owasp_ref="OWASP ASVS V5 / Cross-Site Request Forgery Prevention",
        duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
    )


def _check_cors_info_disclosure(snapshot: ReconSnapshot, order_index: int) -> CheckResult:
    started = time.perf_counter()
    h = snapshot.response_headers
    cors = snapshot.observed_cors_headers

    acao = cors.get("access-control-allow-origin", "")
    acac = cors.get("access-control-allow-credentials", "")
    server_hdr = h.get("server", "")
    powered_by = h.get("x-powered-by", "")
    aspnet_ver = h.get("x-aspnet-version", "")

    evidence: list[str] = [
        f"Access-Control-Allow-Origin: {acao or 'ไม่พบ'}",
        f"Access-Control-Allow-Credentials: {acac or 'ไม่พบ'}",
        f"Server header: {server_hdr or 'ไม่เปิดเผย'}",
        f"X-Powered-By: {powered_by or 'ไม่เปิดเผย'}",
    ]
    if aspnet_ver:
        evidence.append(f"X-AspNet-Version: {aspnet_ver}")

    recommendations: list[str] = []
    score = 100

    cors_fail = acao.strip() == "*" and acac.strip().lower() == "true"
    cors_warn = acao.strip() == "*" and not cors_fail

    if cors_fail:
        score -= 50
        recommendations.append("ห้ามใช้ Access-Control-Allow-Origin: * ร่วมกับ Access-Control-Allow-Credentials: true ให้ระบุ Origin ที่อนุญาตอย่างเจาะจง")
    elif cors_warn:
        score -= 20
        recommendations.append("ตรวจสอบว่าหน้าเว็บนี้จำเป็นต้องเปิด Access-Control-Allow-Origin: * หรือไม่ หากไม่จำเป็นควรจำกัดเฉพาะ Origin ที่เชื่อถือ")

    banner_leaks: list[str] = []
    if powered_by:
        banner_leaks.append("X-Powered-By")
        score -= 15
    if aspnet_ver:
        banner_leaks.append("X-AspNet-Version")
        score -= 15
    if server_hdr and any(ch.isdigit() for ch in server_hdr):
        banner_leaks.append("Server (มีเลขเวอร์ชัน)")
        score -= 10

    if banner_leaks:
        recommendations.append(f"ซ่อนหรือลดรายละเอียด Header ที่เปิดเผยเทคโนโลยี/เวอร์ชัน ({', '.join(banner_leaks)})")

    score = max(0, score)
    if cors_fail:
        status = "fail"
        summary = "พบการตั้งค่า CORS ที่อันตราย (Wildcard * ร่วมกับ Allow-Credentials)"
    elif cors_warn or banner_leaks:
        status = "warn"
        summary = "พบการเปิดเผยข้อมูลเซิร์ฟเวอร์ผ่าน Header หรือการตั้งค่า CORS แบบเปิดกว้าง"
    else:
        status = "pass"
        summary = "ไม่พบการตั้งค่า CORS ที่เสี่ยง และไม่มีการเปิดเผยเวอร์ชันเทคโนโลยีผ่าน Header"

    return CheckResult(
        check_id="cors_info_disclosure",
        name="นโยบาย CORS และการเปิดเผยข้อมูลเซิร์ฟเวอร์",
        category="Security Misconfiguration",
        order_index=order_index,
        status=status,
        score=score,
        summary=summary,
        evidence=evidence,
        recommendations=recommendations,
        remediation_snippet=(
            "# ตัวอย่าง Nginx: ซ่อนเวอร์ชันและกำหนด Origin เฉพาะ\n"
            "server_tokens off;\n"
            "proxy_hide_header X-Powered-By;"
            if status != "pass"
            else None
        ),
        owasp_ref="OWASP A05:2021 Security Misconfiguration",
        duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
    )


def _check_security_metadata(snapshot: ReconSnapshot, order_index: int) -> CheckResult:
    started = time.perf_counter()
    cache_ctl = snapshot.response_headers.get("cache-control", "")
    sec_txt = snapshot.security_txt_status
    robots_txt = snapshot.robots_txt_status

    evidence = [
        f"/.well-known/security.txt: HTTP {sec_txt if sec_txt is not None else 'ไม่สามารถติดต่อได้'}",
        f"/robots.txt: HTTP {robots_txt if robots_txt is not None else 'ไม่สามารถติดต่อได้'}",
        f"Cache-Control: {cache_ctl or 'ไม่พบ'}",
    ]
    recommendations: list[str] = []
    score = 100

    has_sensitive_forms = any(f.has_password_input for f in snapshot.forms)
    weak_cache = has_sensitive_forms and ("no-store" not in cache_ctl.lower())

    if sec_txt != 200:
        score -= 15
        recommendations.append("พิจารณาเพิ่มไฟล์ /.well-known/security.txt (RFC 9116) เพื่อระบุช่องทางแจ้งเตือนช่องโหว่ด้านความปลอดภัยอย่างเป็นทางการ")

    if weak_cache:
        score -= 25
        recommendations.append("หน้าเว็บที่มีฟอร์มกรอกรหัสผ่านควรตั้ง Cache-Control: no-store เพื่อไม่ให้แคชข้อมูลอ่อนไหว")

    if weak_cache:
        status = "warn"
        summary = "หน้าเว็บที่มีฟอร์มรหัสผ่านยังไม่ได้กำหนด Cache-Control: no-store และ/หรือยังไม่มี security.txt"
    elif sec_txt != 200:
        status = "info"
        summary = "ตั้งค่าพื้นฐานเรียบร้อย แต่ยังไม่พบไฟล์ /.well-known/security.txt (RFC 9116)"
    else:
        status = "pass"
        summary = "มีไฟล์ security.txt และนโยบาย Cache Control เหมาะสม"

    return CheckResult(
        check_id="security_metadata",
        name="ไฟล์มาตรฐานความปลอดภัยและ Cache Hygiene",
        category="Operational Security",
        order_index=order_index,
        status=status,
        score=score,
        summary=summary,
        evidence=evidence,
        recommendations=recommendations,
        remediation_snippet=(
            "# ตัวอย่าง /.well-known/security.txt (RFC 9116)\n"
            "Contact: mailto:security@yourdomain.com\n"
            "Expires: 2027-12-31T23:59:59.000Z"
            if sec_txt != 200
            else None
        ),
        owasp_ref="RFC 9116 / OWASP Cache & Operational Security",
        duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
    )


CHECK_DEFINITIONS: dict[str, CheckDefinition] = {
    "https_transport": CheckDefinition(
        id="https_transport",
        name="การเข้ารหัสและการส่งต่อ HTTPS / HSTS",
        category="Transport Security",
        owasp_ref="OWASP ASVS V9.1",
        weight=20,
        runner=_check_https_transport,
    ),
    "security_headers": CheckDefinition(
        id="security_headers",
        name="HTTP Security Headers ตามมาตรฐาน OWASP",
        category="HTTP Headers",
        owasp_ref="OWASP Secure Headers Project",
        weight=20,
        runner=_check_security_headers,
    ),
    "clickjacking_defense": CheckDefinition(
        id="clickjacking_defense",
        name="การป้องกัน Clickjacking และ Framing",
        category="Browser Isolation",
        owasp_ref="OWASP Clickjacking Defense",
        weight=12,
        runner=_check_clickjacking_defense,
    ),
    "cookie_hygiene": CheckDefinition(
        id="cookie_hygiene",
        name="ความปลอดภัยของ Cookie และ Session Flags",
        category="Session Hygiene",
        owasp_ref="OWASP Session Management",
        weight=14,
        runner=_check_cookie_hygiene,
    ),
    "mixed_content_sri": CheckDefinition(
        id="mixed_content_sri",
        name="Mixed Content และ Subresource Integrity (SRI)",
        category="Supply Chain & Integrity",
        owasp_ref="OWASP A08:2021",
        weight=12,
        runner=_check_mixed_content_sri,
    ),
    "form_client_hygiene": CheckDefinition(
        id="form_client_hygiene",
        name="ความปลอดภัยของฟอร์มและลิงก์ฝั่ง Client (DOM)",
        category="Client-Side Hygiene",
        owasp_ref="OWASP ASVS V5",
        weight=10,
        runner=_check_form_client_hygiene,
    ),
    "cors_info_disclosure": CheckDefinition(
        id="cors_info_disclosure",
        name="นโยบาย CORS และการเปิดเผยข้อมูลเซิร์ฟเวอร์",
        category="Security Misconfiguration",
        owasp_ref="OWASP A05:2021",
        weight=8,
        runner=_check_cors_info_disclosure,
    ),
    "security_metadata": CheckDefinition(
        id="security_metadata",
        name="ไฟล์มาตรฐานความปลอดภัยและ Cache Hygiene",
        category="Operational Security",
        owasp_ref="RFC 9116 / OWASP",
        weight=4,
        runner=_check_security_metadata,
    ),
}


def run_single_check(check_id: str, snapshot: ReconSnapshot, order_index: int) -> CheckResult:
    """Execute one registered passive check by ID."""
    definition = CHECK_DEFINITIONS.get(check_id)
    if definition is None:
        raise ValueError(f"ไม่พบหัวข้อการตรวจสอบ: {check_id}")
    return definition.runner(snapshot, order_index)
