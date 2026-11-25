"use strict";

const state = {
  sessionId: null,
  planItems: [],
  currentReport: null,
  dragSrcIndex: null,
};

const els = {
  alertBanner: document.getElementById("alert-banner"),
  reconForm: document.getElementById("recon-form"),
  targetUrl: document.getElementById("target-url"),
  btnAnalyze: document.getElementById("btn-analyze"),
  btnDemoWeak: document.getElementById("btn-demo-weak"),
  btnDemoHardened: document.getElementById("btn-demo-hardened"),
  btnDemoExternal: document.getElementById("btn-demo-external"),
  aiProvider: document.getElementById("ai-provider"),
  aiModel: document.getElementById("ai-model"),
  aiKey: document.getElementById("ai-key"),
  aiBaseUrl: document.getElementById("ai-base-url"),
  wrapAiModel: document.getElementById("wrap-ai-model"),
  wrapAiKey: document.getElementById("wrap-ai-key"),
  wrapAiBase: document.getElementById("wrap-ai-base"),
  sectionPlan: document.getElementById("section-plan"),
  sectionProgress: document.getElementById("section-progress"),
  sectionReport: document.getElementById("section-report"),
  reconMetaLine: document.getElementById("recon-meta-line"),
  planAiBadge: document.getElementById("plan-ai-badge"),
  telemetryStrip: document.getElementById("telemetry-strip"),
  aiPlanSummary: document.getElementById("ai-plan-summary"),
  defenseCountBadge: document.getElementById("defense-count-badge"),
  existingDefensesList: document.getElementById("existing-defenses-list"),
  recommendedChecksList: document.getElementById("recommended-checks-list"),
  selectedCounter: document.getElementById("selected-counter"),
  btnSelectAll: document.getElementById("btn-select-all"),
  btnSelectRec: document.getElementById("btn-select-rec"),
  btnSelectNone: document.getElementById("btn-select-none"),
  btnExecute: document.getElementById("btn-execute"),
  progressCounter: document.getElementById("progress-counter"),
  progressFill: document.getElementById("progress-fill"),
  progressStatusText: document.getElementById("progress-status-text"),
  liveStepsFeed: document.getElementById("live-steps-feed"),
  reportSubtitle: document.getElementById("report-subtitle"),
  reportGrade: document.getElementById("report-grade"),
  reportScore: document.getElementById("report-score"),
  reportCounts: document.getElementById("report-counts"),
  reportExecSummary: document.getElementById("report-exec-summary"),
  reportPriorityList: document.getElementById("report-priority-list"),
  reportResultsList: document.getElementById("report-results-list"),
  btnExportMd: document.getElementById("btn-export-md"),
  btnExportJson: document.getElementById("btn-export-json"),
  btnPrint: document.getElementById("btn-print"),
  btnReset: document.getElementById("btn-reset"),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showAlert(msg) {
  if (!msg) {
    els.alertBanner.classList.add("hidden");
    els.alertBanner.textContent = "";
    return;
  }
  els.alertBanner.textContent = msg;
  els.alertBanner.classList.remove("hidden");
}

function setActiveStep(stepNum) {
  document.querySelectorAll(".step-pill").forEach((pill) => {
    const num = Number(pill.dataset.step);
    pill.classList.toggle("active", num === stepNum);
    pill.classList.toggle("done", num < stepNum);
  });
}

function getAiConfig() {
  const provider = els.aiProvider.value;
  return {
    provider,
    model: els.aiModel.value.trim() || null,
    api_key: els.aiKey.value.trim() || null,
    base_url: els.aiBaseUrl.value.trim() || null,
  };
}

function updateAiFieldVisibility() {
  const p = els.aiProvider.value;
  const showModel = p === "gemini" || p === "openai" || p === "ollama";
  const showKey = p === "gemini" || p === "openai";
  const showBase = p === "openai" || p === "ollama";
  els.wrapAiModel.classList.toggle("hidden", !showModel);
  els.wrapAiKey.classList.toggle("hidden", !showKey);
  els.wrapAiBase.classList.toggle("hidden", !showBase);
}

els.aiProvider.addEventListener("change", updateAiFieldVisibility);

els.btnDemoWeak.addEventListener("click", () => {
  els.targetUrl.value = `${window.location.origin}/demo/vulnerable-config`;
});
els.btnDemoHardened.addEventListener("click", () => {
  els.targetUrl.value = `${window.location.origin}/demo/hardened`;
});
els.btnDemoExternal.addEventListener("click", () => {
  els.targetUrl.value = "https://example.com";
});

els.reconForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  showAlert("");
  const url = els.targetUrl.value.trim();
  if (!url) return;

  els.btnAnalyze.disabled = true;
  els.btnAnalyze.textContent = "กำลังสำรวจด้วย Playwright...";
  els.sectionPlan.classList.add("hidden");
  els.sectionProgress.classList.add("hidden");
  els.sectionReport.classList.add("hidden");

  try {
    const resp = await fetch("/api/recon", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, ai_config: getAiConfig() }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.detail || "ไม่สามารถวิเคราะห์ URL ได้");
    }

    state.sessionId = data.session_id;
    state.planItems = data.recommended_checks.map((item) => ({
      ...item,
      selected: Boolean(item.default_selected),
    }));
    renderReconPlan(data);
    setActiveStep(2);
  } catch (err) {
    showAlert(err.message || "เกิดข้อผิดพลาดระหว่างวิเคราะห์เบื้องต้น");
  } finally {
    els.btnAnalyze.disabled = false;
    els.btnAnalyze.textContent = "วิเคราะห์เบื้องต้น";
  }
});

function renderReconPlan(data) {
  const snap = data.snapshot;
  els.reconMetaLine.textContent = `${snap.final_url} (HTTP ${snap.status_code} • ${snap.recon_duration_ms} ms)`;
  els.planAiBadge.textContent = data.ai_fallback_reason
    ? `${data.ai_mode_used}`
    : `AI: ${data.ai_mode_used}`;

  const pills = [
    `HTTPS: ${snap.is_https ? "Yes" : "No (HTTP)"}`,
    `Playwright: ${snap.playwright_used ? "Active" : "Fallback"}`,
    `Cookies: ${snap.cookies.length}`,
    `Forms: ${snap.forms.length}`,
    `Scripts: ${snap.scripts.length}`,
    `3rd-Party Domains: ${snap.third_party_domains.length}`,
  ];
  els.telemetryStrip.innerHTML = pills
    .map((p) => `<span class="tele-pill">${escapeHtml(p)}</span>`)
    .join("");

  const fallbackHtml = data.ai_fallback_reason
    ? `<div class="muted" style="margin-top:6px;">หมายเหตุ AI Fallback: ${escapeHtml(data.ai_fallback_reason)}</div>`
    : "";
  els.aiPlanSummary.innerHTML = `<strong>สรุปจาก AI Agent:</strong> ${escapeHtml(data.ai_summary)}${fallbackHtml}`;

  els.defenseCountBadge.textContent = String(data.existing_defenses.length);
  if (data.existing_defenses.length === 0) {
    els.existingDefensesList.innerHTML = `<div class="muted">ยังไม่พบการตั้งค่าป้องกันที่โดดเด่นในการสำรวจเบื้องต้น</div>`;
  } else {
    els.existingDefensesList.innerHTML = data.existing_defenses
      .map(
        (d) => `
      <div class="defense-card">
        <h4>✓ ${escapeHtml(d.title)}</h4>
        <p>${escapeHtml(d.description)}</p>
        <code>${escapeHtml(d.evidence)}</code>
      </div>
    `
      )
      .join("");
  }

  renderPlanItems();
  els.sectionPlan.classList.remove("hidden");
  els.sectionPlan.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderPlanItems() {
  let seq = 0;
  els.recommendedChecksList.innerHTML = state.planItems
    .map((item, idx) => {
      if (item.selected) seq += 1;
      const seqLabel = item.selected ? `#${seq}` : "-";
      const prioBadge = `<span class="badge badge-${escapeHtml(item.priority)}">${escapeHtml(item.priority)}</span>`;
      return `
      <div class="check-row ${item.selected ? "" : "unchecked"}" draggable="true" data-index="${idx}">
        <span class="order-num">${seqLabel}</span>
        <input type="checkbox" data-check-idx="${idx}" ${item.selected ? "checked" : ""} aria-label="${escapeHtml(item.name)}">
        <div class="check-body">
          <div class="check-title-line">
            <span class="check-title">${escapeHtml(item.name)}</span>
            ${prioBadge}
          </div>
          <p class="check-reason">${escapeHtml(item.reason)}</p>
        </div>
        <div class="reorder-controls">
          <button type="button" class="btn-icon" data-move-up="${idx}" ${idx === 0 ? "disabled" : ""} title="เลื่อนขึ้น">↑</button>
          <button type="button" class="btn-icon" data-move-down="${idx}" ${idx === state.planItems.length - 1 ? "disabled" : ""} title="เลื่อนลง">↓</button>
        </div>
      </div>
    `;
    })
    .join("");

  const selectedCount = state.planItems.filter((i) => i.selected).length;
  els.selectedCounter.textContent = `เลือกแล้ว ${selectedCount} / ${state.planItems.length} หัวข้อ`;
  els.btnExecute.disabled = selectedCount === 0;
}

els.recommendedChecksList.addEventListener("change", (e) => {
  const idx = e.target.dataset.checkIdx;
  if (idx !== undefined) {
    state.planItems[Number(idx)].selected = e.target.checked;
    renderPlanItems();
  }
});

els.recommendedChecksList.addEventListener("click", (e) => {
  const up = e.target.dataset.moveUp;
  const down = e.target.dataset.moveDown;
  if (up !== undefined) {
    const i = Number(up);
    if (i > 0) {
      [state.planItems[i - 1], state.planItems[i]] = [state.planItems[i], state.planItems[i - 1]];
      renderPlanItems();
    }
  } else if (down !== undefined) {
    const i = Number(down);
    if (i < state.planItems.length - 1) {
      [state.planItems[i + 1], state.planItems[i]] = [state.planItems[i], state.planItems[i + 1]];
      renderPlanItems();
    }
  }
});

els.recommendedChecksList.addEventListener("dragstart", (e) => {
  const row = e.target.closest(".check-row");
  if (!row) return;
  state.dragSrcIndex = Number(row.dataset.index);
  row.classList.add("dragging");
});

els.recommendedChecksList.addEventListener("dragover", (e) => {
  e.preventDefault();
});

els.recommendedChecksList.addEventListener("drop", (e) => {
  e.preventDefault();
  const targetRow = e.target.closest(".check-row");
  if (!targetRow || state.dragSrcIndex === null) return;
  const targetIdx = Number(targetRow.dataset.index);
  if (targetIdx !== state.dragSrcIndex) {
    const [moved] = state.planItems.splice(state.dragSrcIndex, 1);
    state.planItems.splice(targetIdx, 0, moved);
    renderPlanItems();
  }
  state.dragSrcIndex = null;
});

els.recommendedChecksList.addEventListener("dragend", () => {
  state.dragSrcIndex = null;
  document.querySelectorAll(".check-row.dragging").forEach((r) => r.classList.remove("dragging"));
});

els.btnSelectAll.addEventListener("click", () => {
  state.planItems.forEach((i) => { i.selected = true; });
  renderPlanItems();
});

els.btnSelectRec.addEventListener("click", () => {
  state.planItems.forEach((i) => { i.selected = Boolean(i.default_selected); });
  renderPlanItems();
});

els.btnSelectNone.addEventListener("click", () => {
  state.planItems.forEach((i) => { i.selected = false; });
  renderPlanItems();
});

els.btnExecute.addEventListener("click", async () => {
  showAlert("");
  const selectedIds = state.planItems.filter((i) => i.selected).map((i) => i.id);
  if (!state.sessionId || selectedIds.length === 0) return;

  setActiveStep(3);
  els.btnExecute.disabled = true;
  els.sectionReport.classList.add("hidden");
  els.sectionProgress.classList.remove("hidden");
  els.progressFill.style.width = "0%";
  els.progressCounter.textContent = `0 / ${selectedIds.length}`;
  els.progressStatusText.textContent = "กำลังเริ่มรันตัวตรวจสอบตามลำดับ...";
  els.liveStepsFeed.innerHTML = selectedIds
    .map((cid, idx) => {
      const item = state.planItems.find((p) => p.id === cid);
      return `
        <div class="live-step" id="live-step-${escapeHtml(cid)}">
          <span><strong>#${idx + 1}</strong> ${escapeHtml(item ? item.name : cid)}</span>
          <span class="badge badge-info">รอคิว</span>
        </div>
      `;
    })
    .join("");

  els.sectionProgress.scrollIntoView({ behavior: "smooth", block: "start" });

  try {
    const resp = await fetch("/api/execute/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: state.sessionId,
        selected_check_ids: selectedIds,
        ai_config: getAiConfig(),
      }),
    });

    if (!resp.ok || !resp.body) {
      const errData = await resp.json().catch(() => ({}));
      throw new Error(errData.detail || "ไม่สามารถรันการตรวจสอบได้");
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const chunks = buffer.split("\n\n");
      buffer = chunks.pop() || "";

      for (const chunk of chunks) {
        handleSseChunk(chunk);
      }
    }
  } catch (err) {
    showAlert(err.message || "เกิดข้อผิดพลาดระหว่างดำเนินการตรวจสอบ");
  } finally {
    els.btnExecute.disabled = false;
  }
});

function handleSseChunk(chunk) {
  let eventName = "message";
  const dataLines = [];
  for (const line of chunk.split("\n")) {
    if (line.startsWith("event:")) {
      eventName = line.slice(6).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).trim());
    }
  }
  if (dataLines.length === 0) return;

  const payload = JSON.parse(dataLines.join("\n"));

  if (eventName === "check_start") {
    els.progressStatusText.textContent = `กำลังตรวจลำดับที่ ${payload.order_index}/${payload.total_steps}: ${payload.name}`;
    const row = document.getElementById(`live-step-${payload.check_id}`);
    if (row) {
      const badge = row.querySelector(".badge");
      badge.className = "badge badge-medium";
      badge.textContent = "กำลังตรวจ...";
    }
  } else if (eventName === "check_done") {
    const res = payload.result;
    const pct = Math.round((payload.order_index / payload.total_steps) * 90);
    els.progressFill.style.width = `${pct}%`;
    els.progressCounter.textContent = `${payload.order_index} / ${payload.total_steps}`;
    const row = document.getElementById(`live-step-${res.check_id}`);
    if (row) {
      const badge = row.querySelector(".badge");
      badge.className = `badge badge-${res.status}`;
      badge.textContent = `${res.status.toUpperCase()} (${res.score})`;
    }
  } else if (eventName === "summarizing") {
    els.progressFill.style.width = "95%";
    els.progressStatusText.textContent = payload.message || "กำลังสรุปรายงาน...";
  } else if (eventName === "complete") {
    els.progressFill.style.width = "100%";
    els.progressStatusText.textContent = "ตรวจสอบครบทุกขั้นตอนเรียบร้อยแล้ว";
    state.currentReport = payload.report;
    renderFinalReport(payload.report);
    setActiveStep(4);
  }
}

function renderFinalReport(report) {
  els.reportSubtitle.textContent = `เป้าหมาย: ${report.final_url} • AI Mode: ${report.ai_mode_used}`;
  els.reportGrade.textContent = report.grade;
  els.reportGrade.className = `grade-circle grade-${escapeHtml(report.grade)}`;
  els.reportScore.textContent = String(report.overall_score);

  const countLabels = [
    ["pass", "Pass", "badge-pass"],
    ["warn", "Warn", "badge-warn"],
    ["fail", "Fail", "badge-fail"],
    ["info", "Info", "badge-info"],
  ];
  els.reportCounts.innerHTML = countLabels
    .map(
      ([key, label, cls]) => `
    <div class="count-box">
      <strong>${report.counts[key] || 0}</strong>
      <span class="badge ${cls}">${label}</span>
    </div>
  `
    )
    .join("");

  const fallbackNotice = report.ai_fallback_reason
    ? `<div class="muted" style="margin-top:6px;">หมายเหตุ AI Fallback: ${escapeHtml(report.ai_fallback_reason)}</div>`
    : "";
  els.reportExecSummary.innerHTML = `<strong>บทสรุปผู้บริหาร (AI Executive Summary):</strong> ${escapeHtml(report.executive_summary)}${fallbackNotice}`;

  els.reportPriorityList.innerHTML = report.priority_actions
    .map((act) => `<li>${escapeHtml(act)}</li>`)
    .join("");

  els.reportResultsList.innerHTML = report.results
    .map((res) => {
      const evHtml = res.evidence
        .map((e) => `<li><code>${escapeHtml(e)}</code></li>`)
        .join("");
      const recHtml = res.recommendations.length
        ? `<div><strong>คำแนะนำเชิงป้องกัน:</strong><ul class="rec-list">${res.recommendations
            .map((r) => `<li>${escapeHtml(r)}</li>`)
            .join("")}</ul></div>`
        : "";
      const snippetHtml = res.remediation_snippet
        ? `<pre class="snippet-box">${escapeHtml(res.remediation_snippet)}</pre>`
        : "";

      return `
      <article class="result-card">
        <div class="result-head">
          <h4>${res.order_index}. ${escapeHtml(res.name)}</h4>
          <div class="result-meta">
            <span class="muted">${escapeHtml(res.owasp_ref)}</span>
            <span class="badge badge-${escapeHtml(res.status)}">${escapeHtml(res.status)} • ${res.score}/100</span>
          </div>
        </div>
        <p>${escapeHtml(res.summary)}</p>
        <div><strong>หลักฐานที่ตรวจพบ:</strong><ul class="evidence-list">${evHtml}</ul></div>
        ${recHtml}
        ${snippetHtml}
      </article>
    `;
    })
    .join("");

  els.sectionReport.classList.remove("hidden");
  els.sectionReport.scrollIntoView({ behavior: "smooth", block: "start" });
}

els.btnExportMd.addEventListener("click", () => {
  if (!state.currentReport) return;
  window.location.href = `/api/reports/${encodeURIComponent(state.currentReport.report_id)}/export?format=markdown`;
});

els.btnExportJson.addEventListener("click", () => {
  if (!state.currentReport) return;
  window.location.href = `/api/reports/${encodeURIComponent(state.currentReport.report_id)}/export?format=json`;
});

els.btnPrint.addEventListener("click", () => window.print());

els.btnReset.addEventListener("click", () => {
  showAlert("");
  state.sessionId = null;
  state.planItems = [];
  state.currentReport = null;
  els.sectionPlan.classList.add("hidden");
  els.sectionProgress.classList.add("hidden");
  els.sectionReport.classList.add("hidden");
  setActiveStep(1);
  els.targetUrl.focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

updateAiFieldVisibility();
setActiveStep(1);
