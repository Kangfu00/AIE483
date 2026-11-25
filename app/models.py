"""Pydantic schemas for passive reconnaissance, ordered checks, and reporting."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

CheckStatus = Literal["pass", "warn", "fail", "info", "error"]
PriorityLevel = Literal["high", "medium", "low"]
AIProviderType = Literal["auto", "offline", "gemini", "openai", "ollama"]
GradeLevel = Literal["A", "B", "C", "D", "F"]


class AIConfigInput(BaseModel):
    """Per-request AI provider selection (optional)."""

    provider: AIProviderType = "auto"
    api_key: str | None = Field(default=None, max_length=512)
    model: str | None = Field(default=None, max_length=128)
    base_url: str | None = Field(default=None, max_length=512)


class ReconRequest(BaseModel):
    """Request to run initial passive discovery and build an audit plan."""

    url: str = Field(..., min_length=1, max_length=2048)
    ai_config: AIConfigInput | None = None


class CookieSummary(BaseModel):
    """Non-sensitive cookie metadata observed during page load."""

    name: str
    domain: str = ""
    path: str = "/"
    http_only: bool = False
    secure: bool = False
    same_site: str = ""


class ScriptSummary(BaseModel):
    """Metadata for a script element observed in the DOM."""

    src: str = ""
    is_inline: bool = False
    is_external: bool = False
    has_integrity: bool = False
    crossorigin: str = ""


class FormSummary(BaseModel):
    """Passive metadata for an HTML form element."""

    action: str = ""
    method: str = "GET"
    is_insecure_action: bool = False
    has_password_input: bool = False
    has_csrf_like_field: bool = False


class LinkSummary(BaseModel):
    """Metadata for target=_blank links."""

    href: str = ""
    has_noopener: bool = False
    has_noreferrer: bool = False


class ReconSnapshot(BaseModel):
    """Complete read-only telemetry snapshot gathered from target URL."""

    target_url: str
    final_url: str
    scheme: str
    status_code: int
    redirect_chain: list[str] = Field(default_factory=list)
    is_https: bool = False
    http_redirects_to_https: bool | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    set_cookie_count: int = 0
    cookies: list[CookieSummary] = Field(default_factory=list)
    title: str = ""
    scripts: list[ScriptSummary] = Field(default_factory=list)
    forms: list[FormSummary] = Field(default_factory=list)
    blank_links: list[LinkSummary] = Field(default_factory=list)
    iframes_count: int = 0
    mixed_content_urls: list[str] = Field(default_factory=list)
    third_party_domains: list[str] = Field(default_factory=list)
    observed_cors_headers: dict[str, str] = Field(default_factory=dict)
    same_origin_links: list[str] = Field(default_factory=list)
    security_txt_status: int | None = None
    robots_txt_status: int | None = None
    playwright_used: bool = False
    playwright_note: str | None = None
    recon_duration_ms: int = 0


class AgentToolTraceStep(BaseModel):
    """Record of one passive read-only tool invocation by the AI agent."""

    step: int
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    summary: str
    findings: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0


class ExistingDefenseItem(BaseModel):
    """A security control already configured well on the target site."""

    title: str
    category: str
    evidence: str
    description: str


class RecommendedCheckItem(BaseModel):
    """A passive security check suggested for the user to select and order."""

    id: str
    name: str
    category: str
    priority: PriorityLevel
    reason: str
    default_selected: bool = True


class ReconResponse(BaseModel):
    """Response returned to UI after initial passive reconnaissance."""

    session_id: str
    snapshot: ReconSnapshot
    ai_mode_used: str
    ai_fallback_reason: str | None = None
    ai_summary: str
    agent_trace: list[AgentToolTraceStep] = Field(default_factory=list)
    existing_defenses: list[ExistingDefenseItem]
    recommended_checks: list[RecommendedCheckItem]


class ExecutePlanRequest(BaseModel):
    """Request to run user-selected checks in the user-chosen order."""

    session_id: str = Field(..., min_length=1, max_length=128)
    selected_check_ids: list[str] = Field(..., min_length=1, max_length=20)
    ai_config: AIConfigInput | None = None


class CheckResult(BaseModel):
    """Outcome of a single passive security check."""

    check_id: str
    name: str
    category: str
    order_index: int
    status: CheckStatus
    score: int = Field(ge=0, le=100)
    summary: str
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    remediation_snippet: str | None = None
    owasp_ref: str = ""
    duration_ms: int = 0


class CheckDiffItem(BaseModel):
    """Per-check comparison against the previous audit of the same target."""

    check_id: str
    name: str
    previous_status: CheckStatus
    current_status: CheckStatus
    previous_score: int
    current_score: int
    score_delta: int


class ReportDiff(BaseModel):
    """Before/after posture comparison against an earlier saved report."""

    previous_report_id: str
    previous_generated_at: str
    previous_score: int
    previous_grade: GradeLevel
    score_delta: int
    improved: list[CheckDiffItem] = Field(default_factory=list)
    regressed: list[CheckDiffItem] = Field(default_factory=list)
    unchanged_count: int = 0


class ReportHistoryItem(BaseModel):
    """Compact summary row for the audit history list."""

    report_id: str
    target_url: str
    final_url: str
    generated_at: str
    overall_score: int
    grade: GradeLevel
    ai_mode_used: str
    checks_count: int


class SecurityReport(BaseModel):
    """Final compiled Security Posture Report."""

    report_id: str
    session_id: str
    target_url: str
    final_url: str
    generated_at: str
    overall_score: int = Field(ge=0, le=100)
    grade: GradeLevel
    counts: dict[str, int]
    ai_mode_used: str
    ai_fallback_reason: str | None = None
    executive_summary: str
    priority_actions: list[str] = Field(default_factory=list)
    detected_stack: list[str] = Field(default_factory=list)
    stack_advice: str | None = None
    diff_from_previous: ReportDiff | None = None
    existing_defenses: list[ExistingDefenseItem] = Field(default_factory=list)
    results: list[CheckResult] = Field(default_factory=list)
