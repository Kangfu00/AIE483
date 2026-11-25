"""Configuration settings and safe URL validation helpers."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "audit_history.db"


def get_db_path() -> Path:
    """Resolve SQLite history database path dynamically."""
    override = os.getenv("AUDIT_DB_PATH", "").strip()
    return Path(override) if override else DEFAULT_DB_PATH

BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "169.254.169.254",
    "100.100.100.200",
    "0.0.0.0",
}

HTTP_TIMEOUT_SECONDS = 12.0
PLAYWRIGHT_TIMEOUT_MS = 15000
MAX_URL_LENGTH = 2048


@dataclass(frozen=True)
class AISettings:
    """Resolved AI provider settings from environment variables."""

    provider: str
    gemini_api_key: str
    gemini_model: str
    openai_api_key: str
    openai_base_url: str
    openai_model: str
    ollama_base_url: str
    ollama_model: str


def get_ai_settings() -> AISettings:
    """Read current AI configuration from environment variables."""
    return AISettings(
        provider=os.getenv("AI_PROVIDER", "auto").strip().lower() or "auto",
        gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash",
        openai_api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        openai_base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/"),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini",
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.2").strip() or "llama3.2",
    )


def normalize_and_validate_url(raw_url: str) -> str:
    """Validate and normalize a target web URL for passive inspection.

    Only http:// and https:// URLs without embedded credentials or blocked
    cloud-metadata/unspecified addresses are permitted.
    """
    candidate = (raw_url or "").strip()
    if not candidate:
        raise ValueError("กรุณากรอก URL ที่ต้องการตรวจสอบ")

    if len(candidate) > MAX_URL_LENGTH:
        raise ValueError(f"URL ยาวเกินกำหนด (สูงสุด {MAX_URL_LENGTH} ตัวอักษร)")

    lower_candidate = candidate.lower()
    blocked_schemes = ("javascript:", "data:", "vbscript:", "file:", "about:", "blob:")
    if lower_candidate.startswith(blocked_schemes):
        raise ValueError("รองรับเฉพาะ URL ที่ขึ้นต้นด้วย http:// หรือ https:// เท่านั้น")

    if "://" not in candidate:
        if lower_candidate.startswith(("localhost", "127.0.0.1", "[::1]")):
            candidate = f"http://{candidate}"
        else:
            candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("รองรับเฉพาะ URL ที่ขึ้นต้นด้วย http:// หรือ https:// เท่านั้น")

    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("รูปแบบพอร์ตใน URL ไม่ถูกต้อง") from exc

    if not parsed.netloc or not parsed.hostname:
        raise ValueError("รูปแบบ URL ไม่ถูกต้อง (ไม่พบชื่อโฮสต์)")

    if parsed.username or parsed.password:
        raise ValueError("ไม่อนุญาตให้ใส่ username/password ใน URL")

    hostname = parsed.hostname.lower()
    if any(ch.isspace() for ch in hostname):
        raise ValueError("รูปแบบชื่อโฮสต์ใน URL ไม่ถูกต้อง")
    if hostname in BLOCKED_HOSTS:
        raise ValueError("ไม่อนุญาตให้ตรวจสอบที่อยู่ระบบภายใน/Cloud Metadata")

    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_link_local:
            raise ValueError("ไม่อนุญาตให้ตรวจสอบ IP ประเภท link-local, multicast หรือ unspecified")

    return candidate


def validate_llm_base_url(raw_url: str, *, allow_http_local: bool = True) -> str:
    """Validate an LLM API base URL."""
    cleaned = (raw_url or "").strip().rstrip("/")
    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()

    if scheme not in {"http", "https"} or not host:
        raise ValueError("URL ของ LLM Provider ไม่ถูกต้อง")

    if scheme == "http":
        if not (allow_http_local and host in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError("LLM Endpoint ภายนอกต้องเชื่อมต่อผ่าน HTTPS เท่านั้น")

    if host in BLOCKED_HOSTS:
        raise ValueError("LLM Endpoint ไม่อนุญาตให้ชี้ไปยังที่อยู่ metadata")

    return cleaned
