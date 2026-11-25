"use strict";

const state = {
  sessionId: null,
  planItems: [],
  currentReport: null,
  dragSrcIndex: null,
  activeStep: 1,
  isExecuting: false,
};

const els = {
  alertBanner: document.getElementById("alert-banner"),
  reconForm: document.getElementById("recon-form"),
  targetUrl: document.getElementById("target-url"),
  btnAnalyze: document.getElementById("btn-analyze"),
  btnHistory: document.getElementById("btn-history"),
  historyCount: document.getElementById("history-count"),
  sectionHistory: document.getElementById("section-history"),
  btnCloseHistory: document.getElementById("btn-close-history"),
  historyList: document.getElementById("history-list"),
  reconLiveBox: document.getElementById("recon-live-box"),
  reconLiveStatus: document.getElementById("recon-live-status"),
  reconLiveFeed: document.getElementById("recon-live-feed"),
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
  sectionInput: document.getElementById("section-input"),
  sectionPlan: document.getElementById("section-plan"),
  sectionProgress: document.getElementById("section-progress"),
  sectionReport: document.getElementById("section-report"),
  reconMetaLine: document.getElementById("recon-meta-line"),
  planAiBadge: document.getElementById("plan-ai-badge"),
  telemetryStrip: document.getElementById("telemetry-strip"),
  aiPlanSummary: document.getElementById("ai-plan-summary"),
  agentTraceBox: document.getElementById("agent-trace-box"),
  agentTraceCount: document.getElementById("agent-trace-count"),
  agentTraceList: document.getElementById("agent-trace-list"),
  defenseCountBadge: document.getElementById("defense-count-badge"),
  existingDefensesList: document.getElementById("existing-defenses-list"),
  recommendedChecksList: document.getElementById("recommended-checks-list"),
  selectedCounter: document.getElementById("selected-counter"),
  btnSelectAll: document.getElementById("btn-select-all"),
  btnSelectRec: document.getElementById("btn-select-rec"),
  btnSelectNone: document.getElementById("btn-select-none"),
  btnBackToInput: document.getElementById("btn-back-to-input"),
  btnExecute: document.getElementById("btn-execute"),
  progressCounter: document.getElementById("progress-counter"),
  progressFill: document.getElementById("progress-fill"),
  progressStatusText: document.getElementById("progress-status-text"),
  liveStepsFeed: document.getElementById("live-steps-feed"),
  progressErrorFooter: document.getElementById("progress-error-footer"),
  btnProgressBack: document.getElementById("btn-progress-back"),
  reportSubtitle: document.getElementById("report-subtitle"),
  reportGrade: document.getElementById("report-grade"),
  reportScore: document.getElementById("report-score"),
  reportCounts: document.getElementById("report-counts"),
  reportDiffBox: document.getElementById("report-diff-box"),
  reportExecSummary: document.getElementById("report-exec-summary"),
  reportStackBox: document.getElementById("report-stack-box"),
  reportPriorityList: document.getElementById("report-priority-list"),
  reportResultsList: document.getElementById("report-results-list"),
  btnBackToPlan: document.getElementById("btn-back-to-plan"),
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

function canNavigateToStep(stepNum) {
  if (state.isExecuting) return false;
  if (stepNum === 1) return true;
  if (stepNum === 2) return Boolean(state.sessionId);
  if (stepNum === 4) return Boolean(state.currentReport);
  return false;
}

function updateStepper(stepNum) {
  document.querySelectorAll(".step-pill").forEach((pill) => {
    const num = Number(pill.dataset.step);
    const reachable = canNavigateToStep(num) && num !== stepNum;
    pill.classList.toggle("active", num === stepNum);
    pill.classList.toggle("done", num < stepNum || (num === 2 && Boolean(state.sessionId) && stepNum > 2) || (num === 4 && Boolean(state.currentReport) && stepNum !== 4));
    pill.classList.toggle("clickable", reachable);
    pill.disabled = !canNavigateToStep(num) || num === stepNum;
  });
}

function goToStep(stepNum, { scroll = true } = {}) {
  state.activeStep = stepNum;
  els.sectionInput.classList.toggle("hidden", stepNum !== 1);
  els.sectionPlan.classList.toggle("hidden", stepNum !== 2);
  els.sectionProgress.classList.toggle("hidden", stepNum !== 3);
  els.sectionReport.classList.toggle("hidden", stepNum !== 4);
  updateStepper(stepNum);
  if (scroll) {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}

document.querySelectorAll(".step-pill").forEach((pill) => {
  pill.addEventListener("click", () => {
    const target = Number(pill.dataset.step);
    if (canNavigateToStep(target) && target !== state.activeStep) {
      showAlert("");
      goToStep(target);
    }
  });
});

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
  hopSpider();
  setSpiderEmote("inspecting", 2.0, "WEAK TARGET?");
});
els.btnDemoHardened.addEventListener("click", () => {
  els.targetUrl.value = `${window.location.origin}/demo/hardened`;
  hopSpider();
  setSpiderEmote("shield", 2.0, "HARDENED?");
});
els.btnDemoExternal.addEventListener("click", () => {
  els.targetUrl.value = "https://example.com";
  hopSpider();
  setSpiderEmote("inspecting", 2.0, "TARGET SET!");
});

els.targetUrl.addEventListener("focus", () => {
  if (state.activeStep === 1 && !state.isExecuting) {
    setSpiderEmote("reading", 1.8, "INPUT URL...");
  }
});

async function streamSsePost(url, bodyObj, onEvent) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(bodyObj),
  });
  if (!resp.ok || !resp.body) {
    const errData = await resp.json().catch(() => ({}));
    throw new Error(errData.detail || "ไม่สามารถเชื่อมต่อสตรีมได้");
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
      let eventName = "message";
      const dataLines = [];
      for (const line of chunk.split("\n")) {
        if (line.startsWith("event:")) {
          eventName = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          dataLines.push(line.slice(5).trim());
        }
      }
      if (dataLines.length === 0) continue;
      onEvent(eventName, JSON.parse(dataLines.join("\n")));
    }
  }
}

async function refreshHistoryCount() {
  try {
    const resp = await fetch("/api/reports?limit=30");
    if (!resp.ok) return [];
    const items = await resp.json();
    if (els.historyCount) {
      els.historyCount.textContent = String(items.length);
    }
    return items;
  } catch {
    return [];
  }
}

async function openHistoryDrawer() {
  const items = await refreshHistoryCount();
  if (items.length === 0) {
    els.historyList.innerHTML = `<div class="muted">ยังไม่มีประวัติรายงานที่บันทึกไว้</div>`;
  } else {
    els.historyList.innerHTML = items
      .map(
        (it) => `
      <button type="button" class="history-row" data-report-id="${escapeHtml(it.report_id)}">
        <div>
          <strong>${escapeHtml(it.final_url)}</strong>
          <div class="muted">${escapeHtml(it.generated_at.slice(0, 19).replace("T", " "))} • ${escapeHtml(it.ai_mode_used)} • ${it.checks_count} checks</div>
        </div>
        <span class="badge badge-${it.grade === "A" || it.grade === "B" ? "pass" : it.grade === "C" ? "warn" : "fail"}">
          GRADE ${escapeHtml(it.grade)} (${it.overall_score}/100)
        </span>
      </button>
    `
      )
      .join("");
  }
  els.sectionHistory.classList.remove("hidden");
}

els.btnHistory?.addEventListener("click", () => {
  if (els.sectionHistory.classList.contains("hidden")) {
    openHistoryDrawer();
  } else {
    els.sectionHistory.classList.add("hidden");
  }
});

els.btnCloseHistory?.addEventListener("click", () => {
  els.sectionHistory.classList.add("hidden");
});

els.historyList?.addEventListener("click", async (e) => {
  const row = e.target.closest("[data-report-id]");
  if (!row) return;
  const rid = row.dataset.reportId;
  try {
    const resp = await fetch(`/api/reports/${encodeURIComponent(rid)}`);
    if (!resp.ok) throw new Error("โหลดรายงานไม่สำเร็จ");
    const report = await resp.json();
    state.currentReport = report;
    els.sectionHistory.classList.add("hidden");
    renderFinalReport(report);
    goToStep(4);
    setSpiderMode("idle", `LOADED ${report.grade}!`, "reading");
  } catch (err) {
    showAlert(err.message);
  }
});

function appendReconLiveRow(label, detail, badgeText = "DONE") {
  const row = document.createElement("div");
  row.className = "recon-live-row";
  row.innerHTML = `<span><code>${escapeHtml(label)}</code> ${escapeHtml(detail)}</span><span class="muted">${escapeHtml(badgeText)}</span>`;
  els.reconLiveFeed.appendChild(row);
}

els.reconForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  showAlert("");
  const url = els.targetUrl.value.trim();
  if (!url) return;

  els.btnAnalyze.disabled = true;
  els.btnAnalyze.textContent = "กำลังสำรวจและเรียกเครื่องมือ...";
  els.reconLiveBox.classList.remove("hidden");
  els.reconLiveStatus.textContent = "RUNNING";
  els.reconLiveFeed.innerHTML = "";
  hopSpider();
  setSpiderMode("scanning", "PLAYWRIGHT RECON!");

  let reconResult = null;
  let streamError = null;

  try {
    await streamSsePost("/api/recon/stream", { url, ai_config: getAiConfig() }, (ev, payload) => {
      if (ev === "recon_start") {
        els.reconLiveStatus.textContent = "PLAYWRIGHT";
        appendReconLiveRow("RECON", payload.message, "ACTIVE");
      } else if (ev === "recon_done") {
        els.reconLiveStatus.textContent = "AGENT";
        appendReconLiveRow("HTTP", payload.message, `${payload.recon_duration_ms} ms`);
      } else if (ev === "agent_status") {
        appendReconLiveRow("AGENT", payload.message, "THINKING");
      } else if (ev === "tool_start") {
        els.reconLiveStatus.textContent = `TOOL #${payload.step}`;
        setSpiderEmote("inspecting", 2.0, payload.tool_name.toUpperCase());
      } else if (ev === "tool_done") {
        appendReconLiveRow(`#${payload.step} ${payload.tool_name}`, payload.summary, `${payload.duration_ms} ms`);
      } else if (ev === "complete") {
        reconResult = payload.recon;
      } else if (ev === "error") {
        streamError = payload.detail || "เกิดข้อผิดพลาดระหว่างวิเคราะห์";
      }
    });

    if (streamError) throw new Error(streamError);
    if (!reconResult) throw new Error("ไม่ได้รับข้อมูลผลการสำรวจจากเซิร์ฟเวอร์");

    state.sessionId = reconResult.session_id;
    state.currentReport = null;
    state.planItems = reconResult.recommended_checks.map((item) => ({
      ...item,
      selected: Boolean(item.default_selected),
    }));
    renderReconPlan(reconResult);
    els.reconLiveBox.classList.add("hidden");
    goToStep(2);
    setSpiderMode("idle", `${reconResult.existing_defenses.length} DEFENSES!`, "reading");
  } catch (err) {
    setSpiderMode("idle", "SCAN ERROR", "shield");
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

  const trace = Array.isArray(data.agent_trace) ? data.agent_trace : [];
  els.agentTraceCount.textContent = `${trace.length} tools`;
  if (trace.length === 0) {
    els.agentTraceBox.classList.add("hidden");
  } else {
    els.agentTraceBox.classList.remove("hidden");
    els.agentTraceList.innerHTML = trace
      .map(
        (t) => `
      <div class="trace-item">
        <div class="trace-item-head">
          <span><strong>#${t.step}</strong> <code>${escapeHtml(t.tool_name)}</code></span>
          <span class="muted">${t.duration_ms} ms</span>
        </div>
        <div>${escapeHtml(t.summary)}</div>
      </div>
    `
      )
      .join("");
  }

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
    const count = state.planItems.filter((i) => i.selected).length;
    setSpiderEmote("inspecting", 1.3, `QUEUED: ${count}`);
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
      setSpiderEmote("shield", 1.1, "ORDER UP!");
    }
  } else if (down !== undefined) {
    const i = Number(down);
    if (i < state.planItems.length - 1) {
      [state.planItems[i + 1], state.planItems[i]] = [state.planItems[i], state.planItems[i + 1]];
      renderPlanItems();
      setSpiderEmote("shield", 1.1, "ORDER DOWN!");
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
    setSpiderEmote("shield", 1.1, "REORDERED!");
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
  setSpiderEmote("happy", 1.3, `ALL ${state.planItems.length}!`);
});

els.btnSelectRec.addEventListener("click", () => {
  state.planItems.forEach((i) => { i.selected = Boolean(i.default_selected); });
  renderPlanItems();
  setSpiderEmote("reading", 1.4, "AI PICKS!");
});

els.btnSelectNone.addEventListener("click", () => {
  state.planItems.forEach((i) => { i.selected = false; });
  renderPlanItems();
  setSpiderEmote("coffee", 1.2, "CLEARED!");
});

els.btnBackToInput.addEventListener("click", () => {
  showAlert("");
  goToStep(1);
  setSpiderEmote("inspecting", 1.5, "NEW TARGET?");
  els.targetUrl.focus();
});

els.btnProgressBack.addEventListener("click", () => {
  showAlert("");
  goToStep(2);
  setSpiderEmote("reading", 1.5, "EDIT PLAN");
});

els.btnBackToPlan.addEventListener("click", () => {
  showAlert("");
  goToStep(2);
  setSpiderEmote("reading", 1.5, "EDIT PLAN");
});

els.btnExecute.addEventListener("click", async () => {
  showAlert("");
  const selectedIds = state.planItems.filter((i) => i.selected).map((i) => i.id);
  if (!state.sessionId || selectedIds.length === 0) return;

  state.isExecuting = true;
  els.btnExecute.disabled = true;
  setSpiderMode("scanning", "CHECKING...");
  els.progressErrorFooter.classList.add("hidden");
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

  goToStep(3);

  try {
    await streamSsePost(
      "/api/execute/stream",
      {
        session_id: state.sessionId,
        selected_check_ids: selectedIds,
        ai_config: getAiConfig(),
      },
      (eventName, payload) => {
        handleSsePayload(eventName, payload);
      }
    );
  } catch (err) {
    setSpiderMode("idle");
    showAlert(err.message || "เกิดข้อผิดพลาดระหว่างดำเนินการตรวจสอบ");
    els.progressErrorFooter.classList.remove("hidden");
  } finally {
    state.isExecuting = false;
    els.btnExecute.disabled = false;
    updateStepper(state.activeStep);
  }
});

function handleSsePayload(eventName, payload) {

  if (eventName === "check_start") {
    els.progressStatusText.textContent = `กำลังตรวจลำดับที่ ${payload.order_index}/${payload.total_steps}: ${payload.name}`;
    const row = document.getElementById(`live-step-${payload.check_id}`);
    if (row) {
      const badge = row.querySelector(".badge");
      badge.className = "badge badge-medium";
      badge.textContent = "กำลังตรวจ...";
    }
    hopSpider();
    setSpiderEmote("inspecting", 1.8, `CHECKING #${payload.order_index}`);
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
    if (res.status === "pass") {
      setSpiderEmote("happy", 1.2, `#${res.order_index} PASS!`);
    } else if (res.status === "fail") {
      setSpiderEmote("shield", 1.2, `#${res.order_index} FAIL!`);
    } else {
      setSpiderEmote("reading", 1.2, `#${res.order_index} ${res.status.toUpperCase()}`);
    }
  } else if (eventName === "summarizing") {
    els.progressFill.style.width = "95%";
    els.progressStatusText.textContent = payload.message || "กำลังสรุปรายงาน...";
    setSpiderEmote("reading", 2.2, "WRITING REPORT...");
  } else if (eventName === "complete") {
    els.progressFill.style.width = "100%";
    els.progressStatusText.textContent = "ตรวจสอบครบทุกขั้นตอนเรียบร้อยแล้ว";
    state.isExecuting = false;
    state.currentReport = payload.report;
    renderFinalReport(payload.report);
    goToStep(4);
    const grade = payload.report.grade;
    const score = payload.report.overall_score;
    const gradeEmote = grade === "A" || grade === "B" ? "happy" : grade === "C" ? "reading" : "shield";
    const gradeMsg = grade === "A" || grade === "B" ? `GRADE ${grade}! (${score})` : `GRADE ${grade}! FIX!`;
    setSpiderMode("idle", gradeMsg, gradeEmote);
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

  if (report.diff_from_previous) {
    const d = report.diff_from_previous;
    const sign = d.score_delta >= 0 ? "+" : "";
    const cls = d.score_delta > 0 ? "badge-pass" : d.score_delta < 0 ? "badge-fail" : "badge-info";
    const impText = d.improved.length
      ? `<div class="muted" style="margin-top:4px;">ดีขึ้น: ${d.improved.map((i) => escapeHtml(i.name)).join(", ")}</div>`
      : "";
    const regText = d.regressed.length
      ? `<div class="muted" style="margin-top:4px;">ลดลง: ${d.regressed.map((i) => escapeHtml(i.name)).join(", ")}</div>`
      : "";
    els.reportDiffBox.innerHTML = `
      <strong>เทียบกับประวัติครั้งก่อน:</strong>
      <span class="badge ${cls}">${sign}${d.score_delta} คะแนน</span>
      <span>${d.previous_score} (${escapeHtml(d.previous_grade)}) → ${report.overall_score} (${escapeHtml(report.grade)})</span>
      ${impText}${regText}
    `;
    els.reportDiffBox.classList.remove("hidden");
  } else {
    els.reportDiffBox.classList.add("hidden");
  }

  const stackList = Array.isArray(report.detected_stack) ? report.detected_stack : [];
  if (stackList.length > 0 || report.stack_advice) {
    const chips = stackList.map((s) => `<span class="tele-pill">${escapeHtml(s)}</span>`).join("");
    els.reportStackBox.innerHTML = `
      <div class="stack-chips">${chips}</div>
      <div><strong>คำแนะนำจาก Advisor Agent ตาม Stack:</strong> ${escapeHtml(report.stack_advice || "")}</div>
    `;
    els.reportStackBox.classList.remove("hidden");
  } else {
    els.reportStackBox.classList.add("hidden");
  }

  refreshHistoryCount();

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
}

els.btnExportMd.addEventListener("click", () => {
  if (!state.currentReport) return;
  setSpiderEmote("happy", 1.6, "EXPORTED MD!");
  window.location.href = `/api/reports/${encodeURIComponent(state.currentReport.report_id)}/export?format=markdown`;
});

els.btnExportJson.addEventListener("click", () => {
  if (!state.currentReport) return;
  setSpiderEmote("happy", 1.6, "EXPORTED JSON!");
  window.location.href = `/api/reports/${encodeURIComponent(state.currentReport.report_id)}/export?format=json`;
});

els.btnPrint.addEventListener("click", () => {
  setSpiderEmote("reading", 1.4, "PRINT READY!");
  window.print();
});

els.btnReset.addEventListener("click", () => {
  showAlert("");
  state.sessionId = null;
  state.planItems = [];
  state.currentReport = null;
  goToStep(1);
  setSpiderMode("idle", "READY!", "shield");
  els.targetUrl.focus();
});

const SPIDER_EMOTES = [
  { name: "inspecting", bubble: "SCANNING..." },
  { name: "reading", bubble: "READING OWASP..." },
  { name: "coffee", bubble: "COFFEE BREAK~" },
  { name: "shield", bubble: "PASSIVE SHIELD!" },
  { name: "happy", bubble: "HAPPY GUARD!" },
  { name: "webbing", bubble: "THWIP! WEB!" },
];

const spiderCtrl = {
  layer: document.getElementById("spider-roam-layer"),
  webSvg: document.getElementById("spider-web-svg"),
  btnWebShot: document.getElementById("btn-spider-web"),
  el: document.getElementById("pixel-spider"),
  bubble: document.getElementById("spider-bubble"),
  x: 32,
  y: 120,
  vx: 58,
  vy: 34,
  mode: "idle",
  emote: "",
  emoteFor: 0,
  emoteIdx: 0,
  lastTs: 0,
  stepAccum: 0,
  nextTurnIn: 2.2,
  pauseFor: 0,
  boostFor: 0,
  zipTarget: null,
  activeLine: null,
  isGrabbed: false,
  dragMoved: false,
  dragStartX: 0,
  dragStartY: 0,
  dragOffsetX: 0,
  dragOffsetY: 0,
  bubbleTimer: null,
};

function createSvgEl(tag, attrs) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) {
    node.setAttribute(k, String(v));
  }
  return node;
}

function buildPixelCobwebGroup(cx, cy) {
  const g = createSvgEl("g", { class: "pixel-cobweb" });
  const px = 3;
  // Crisp pixel art cobweb cross + diagonal arms + inner ring
  const blocks = [
    [0, 0, "#38bdf8"],
    [-1, 0, "#cbd5e1"], [1, 0, "#cbd5e1"], [0, -1, "#cbd5e1"], [0, 1, "#cbd5e1"],
    [-2, 0, "#94a3b8"], [2, 0, "#94a3b8"], [0, -2, "#94a3b8"], [0, 2, "#94a3b8"],
    [-3, 0, "#64748b"], [3, 0, "#64748b"], [0, -3, "#64748b"], [0, 3, "#64748b"],
    [-1, -1, "#38bdf8"], [1, -1, "#38bdf8"], [-1, 1, "#38bdf8"], [1, 1, "#38bdf8"],
    [-2, -2, "#cbd5e1"], [2, -2, "#cbd5e1"], [-2, 2, "#cbd5e1"], [2, 2, "#cbd5e1"],
    [-3, -3, "#64748b"], [3, -3, "#64748b"], [-3, 3, "#64748b"], [3, 3, "#64748b"],
    [-2, -1, "#475569"], [2, -1, "#475569"], [-2, 1, "#475569"], [2, 1, "#475569"],
    [-1, -2, "#475569"], [1, -2, "#475569"], [-1, 2, "#475569"], [1, 2, "#475569"],
  ];
  for (const [dx, dy, fill] of blocks) {
    g.appendChild(
      createSvgEl("rect", {
        x: Math.round(cx + dx * px - 1),
        y: Math.round(cy + dy * px - 1),
        width: px,
        height: px,
        fill,
      })
    );
  }
  return g;
}

function shootWebTo(
  targetX,
  targetY,
  {
    grapple = true,
    shootBubble = "THWIP!",
    afterEmote = "happy",
    afterBubble = "WEB LANDED!",
  } = {}
) {
  if (!spiderCtrl.webSvg || !spiderCtrl.el) return;

  const clampedX = Math.max(24, Math.min(window.innerWidth - 24, targetX));
  const clampedY = Math.max(24, Math.min(window.innerHeight - 24, targetY));

  const startX = spiderCtrl.x + 44;
  const startY = spiderCtrl.y + 36;
  spiderCtrl.vx = clampedX >= startX ? Math.abs(spiderCtrl.vx) : -Math.abs(spiderCtrl.vx);
  updateSpiderTransform();

  setSpiderEmote("webbing", 1.1, shootBubble);

  const shotGroup = createSvgEl("g", { class: "pixel-web-shot" });
  const silkLine = createSvgEl("line", {
    x1: Math.round(startX),
    y1: Math.round(startY),
    x2: Math.round(clampedX),
    y2: Math.round(clampedY),
    stroke: "#e2e8f0",
    "stroke-width": "3",
    "stroke-dasharray": "6 4",
  });
  const silkGlow = createSvgEl("line", {
    x1: Math.round(startX),
    y1: Math.round(startY),
    x2: Math.round(clampedX),
    y2: Math.round(clampedY),
    stroke: "#38bdf8",
    "stroke-width": "1.5",
    opacity: "0.75",
  });
  const cobweb = buildPixelCobwebGroup(clampedX, clampedY);

  shotGroup.appendChild(silkGlow);
  shotGroup.appendChild(silkLine);
  shotGroup.appendChild(cobweb);
  spiderCtrl.webSvg.appendChild(shotGroup);

  // Cap active webs on screen
  while (spiderCtrl.webSvg.children.length > 6) {
    spiderCtrl.webSvg.removeChild(spiderCtrl.webSvg.firstChild);
  }

  if (grapple) {
    spiderCtrl.pauseFor = 0;
    spiderCtrl.zipTarget = {
      x: Math.max(10, Math.min(window.innerWidth - 96, clampedX - 44)),
      y: Math.max(10, Math.min(window.innerHeight - 80, clampedY - 36)),
      anchorX: clampedX,
      anchorY: clampedY,
      silkLine,
      silkGlow,
      afterEmote,
      afterBubble,
    };
  }

  setTimeout(() => {
    shotGroup.classList.add("fading");
    setTimeout(() => shotGroup.remove(), 650);
  }, 3400);
}

function hopSpider() {
  if (!spiderCtrl.el) return;
  spiderCtrl.el.classList.add("is-hopping");
  setTimeout(() => spiderCtrl.el.classList.remove("is-hopping"), 200);
}

function pickContextIdleEmote() {
  if (state.activeStep === 1) {
    const step1 = [
      { name: "shield", bubble: "PASSIVE GUARD" },
      { name: "inspecting", bubble: "READY TO SCAN" },
      { name: "coffee", bubble: "WAITING URL~" },
    ];
    return step1[Math.floor(Math.random() * step1.length)];
  }
  if (state.activeStep === 2) {
    const step2 = [
      { name: "reading", bubble: "REVIEW PLAN" },
      { name: "inspecting", bubble: "CHECK ORDER?" },
      { name: "coffee", bubble: "PICK TESTS~" },
    ];
    return step2[Math.floor(Math.random() * step2.length)];
  }
  if (state.activeStep === 4 && state.currentReport) {
    const grade = state.currentReport.grade;
    if (grade === "A" || grade === "B") {
      return Math.random() < 0.5
        ? { name: "happy", bubble: `GRADE ${grade}!` }
        : { name: "shield", bubble: "STRONG CONFIG!" };
    }
    return Math.random() < 0.5
      ? { name: "reading", bubble: "READ FIXES!" }
      : { name: "shield", bubble: "HARDEN HEADERS!" };
  }
  return SPIDER_EMOTES[Math.floor(Math.random() * SPIDER_EMOTES.length)];
}

function shootRandomWeb({ grapple = true } = {}) {
  const margin = 60;
  const rx = margin + Math.random() * Math.max(80, window.innerWidth - margin * 2);
  const ry = margin + Math.random() * Math.max(80, window.innerHeight - margin * 2);
  shootWebTo(rx, ry, { grapple });
}

function showSpiderBubble(text, ms = 2200) {
  if (!spiderCtrl.bubble) return;
  if (spiderCtrl.bubbleTimer) clearTimeout(spiderCtrl.bubbleTimer);
  spiderCtrl.bubble.textContent = text;
  spiderCtrl.bubble.classList.remove("hidden");
  spiderCtrl.bubbleTimer = setTimeout(() => {
    spiderCtrl.bubble.classList.add("hidden");
  }, ms);
}

function setSpiderEmote(emoteName, durationSec = 2.6, bubbleText = "") {
  SPIDER_EMOTES.forEach((em) => spiderCtrl.el?.classList.remove(`emote-${em.name}`));
  spiderCtrl.emote = emoteName || "";
  spiderCtrl.emoteFor = emoteName ? durationSec : 0;
  if (emoteName && spiderCtrl.el) {
    spiderCtrl.el.classList.add(`emote-${emoteName}`);
  }
  if (bubbleText) {
    showSpiderBubble(bubbleText, Math.round(durationSec * 1000));
  }
}

function setSpiderMode(mode, message = "", forcedEmote = "") {
  spiderCtrl.mode = mode;
  if (mode === "scanning") {
    setSpiderEmote("inspecting", 4.0, message);
  } else if (forcedEmote) {
    spiderCtrl.zipTarget = null;
    setSpiderEmote(forcedEmote, 3.0, message);
  } else if (message) {
    showSpiderBubble(message, 2500);
  }
}

function pickNewSpiderVelocity() {
  const angle = Math.random() * Math.PI * 2;
  const baseSpeed = spiderCtrl.mode === "scanning" ? 135 : 64;
  spiderCtrl.vx = Math.cos(angle) * baseSpeed;
  spiderCtrl.vy = Math.sin(angle) * baseSpeed;
  if (Math.abs(spiderCtrl.vx) < 22) {
    spiderCtrl.vx = (spiderCtrl.vx >= 0 ? 1 : -1) * 36;
  }
}

function updateSpiderTransform() {
  const maxW = Math.max(90, window.innerWidth - 96);
  const maxH = Math.max(90, window.innerHeight - 80);
  spiderCtrl.x = Math.min(maxW, Math.max(10, spiderCtrl.x));
  spiderCtrl.y = Math.min(maxH, Math.max(10, spiderCtrl.y));

  spiderCtrl.el.style.transform = `translate3d(${Math.round(spiderCtrl.x)}px, ${Math.round(spiderCtrl.y)}px, 0)`;
  spiderCtrl.el.classList.toggle("facing-left", spiderCtrl.vx < 0);

  if (spiderCtrl.bubble) {
    spiderCtrl.bubble.classList.toggle("bubble-below", spiderCtrl.y < 84);
    spiderCtrl.bubble.classList.toggle("align-left", spiderCtrl.x < 96);
    spiderCtrl.bubble.classList.toggle("align-right", spiderCtrl.x > window.innerWidth - 170);
  }
}

function triggerNextEmote() {
  const em = SPIDER_EMOTES[spiderCtrl.emoteIdx % SPIDER_EMOTES.length];
  spiderCtrl.emoteIdx += 1;
  if (em.name === "webbing") {
    shootRandomWeb({ grapple: true });
    return;
  }
  spiderCtrl.pauseFor = 2.4;
  setSpiderEmote(em.name, 2.4, em.bubble);
}

function startSpiderPatrol() {
  if (!spiderCtrl.layer || !spiderCtrl.el) return;
  const reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  spiderCtrl.x = Math.min(window.innerWidth - 120, Math.max(24, Math.round(window.innerWidth * 0.72)));
  spiderCtrl.y = 92;
  updateSpiderTransform();

  if (spiderCtrl.btnWebShot) {
    spiderCtrl.btnWebShot.addEventListener("click", () => {
      shootRandomWeb({ grapple: true });
    });
  }

  spiderCtrl.el.addEventListener("dblclick", (e) => {
    e.preventDefault();
    shootRandomWeb({ grapple: true });
  });

  spiderCtrl.el.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    shootRandomWeb({ grapple: true });
  });

  spiderCtrl.el.addEventListener("pointerdown", (e) => {
    if (e.button === 2) return;
    e.preventDefault();
    spiderCtrl.zipTarget = null;
    spiderCtrl.isGrabbed = true;
    spiderCtrl.dragMoved = false;
    spiderCtrl.dragStartX = e.clientX;
    spiderCtrl.dragStartY = e.clientY;
    spiderCtrl.dragOffsetX = e.clientX - spiderCtrl.x;
    spiderCtrl.dragOffsetY = e.clientY - spiderCtrl.y;
    spiderCtrl.el.classList.add("is-grabbed");
    setSpiderEmote("", 0);
    if (spiderCtrl.el.setPointerCapture) {
      try {
        spiderCtrl.el.setPointerCapture(e.pointerId);
      } catch {
        // Ignore capture errors in synthetic tests
      }
    }
  });

  window.addEventListener("pointermove", (e) => {
    if (!spiderCtrl.isGrabbed) return;
    const dist = Math.hypot(e.clientX - spiderCtrl.dragStartX, e.clientY - spiderCtrl.dragStartY);
    if (dist > 5 && !spiderCtrl.dragMoved) {
      spiderCtrl.dragMoved = true;
      showSpiderBubble("WHEEE!", 1600);
    }
    if (spiderCtrl.dragMoved) {
      const nextX = e.clientX - spiderCtrl.dragOffsetX;
      if (Math.abs(nextX - spiderCtrl.x) > 1) {
        spiderCtrl.vx = nextX >= spiderCtrl.x ? Math.abs(spiderCtrl.vx) : -Math.abs(spiderCtrl.vx);
      }
      spiderCtrl.x = nextX;
      spiderCtrl.y = e.clientY - spiderCtrl.dragOffsetY;
      updateSpiderTransform();
    }
  });

  function endDrag(e) {
    if (!spiderCtrl.isGrabbed) return;
    spiderCtrl.isGrabbed = false;
    spiderCtrl.el.classList.remove("is-grabbed");
    if (spiderCtrl.el.releasePointerCapture && e.pointerId !== undefined) {
      try {
        spiderCtrl.el.releasePointerCapture(e.pointerId);
      } catch {
        // Ignore
      }
    }

    if (spiderCtrl.dragMoved) {
      hopSpider();
      spiderCtrl.pauseFor = 1.4;
      setSpiderEmote("happy", 1.4, "SAFE SPOT!");
    } else {
      hopSpider();
      triggerNextEmote();
    }
  }

  window.addEventListener("pointerup", endDrag);
  window.addEventListener("pointercancel", endDrag);

  // Also trigger emote on keyboard / synthetic click if not preceded by pointer drag
  spiderCtrl.el.addEventListener("click", (e) => {
    if (e.detail === 0) {
      triggerNextEmote();
    }
  });

  window.addEventListener("resize", updateSpiderTransform);

  if (reducedMotion) {
    return;
  }

  function tick(ts) {
    if (!spiderCtrl.lastTs) spiderCtrl.lastTs = ts;
    const dt = Math.min(0.05, (ts - spiderCtrl.lastTs) / 1000);
    spiderCtrl.lastTs = ts;

    if (spiderCtrl.isGrabbed) {
      spiderCtrl.stepAccum += dt * 12;
      spiderCtrl.el.classList.toggle("step-b", Math.floor(spiderCtrl.stepAccum) % 2 === 1);
      requestAnimationFrame(tick);
      return;
    }

    if (spiderCtrl.zipTarget) {
      const z = spiderCtrl.zipTarget;
      const dx = z.x - spiderCtrl.x;
      const dy = z.y - spiderCtrl.y;
      const dist = Math.hypot(dx, dy);
      const zipStep = 440 * dt;

      if (dist <= zipStep + 4) {
        spiderCtrl.x = z.x;
        spiderCtrl.y = z.y;
        z.silkLine.setAttribute("opacity", "0.35");
        z.silkGlow.setAttribute("opacity", "0.2");
        spiderCtrl.zipTarget = null;
        spiderCtrl.pauseFor = 0.85;
        hopSpider();
        setSpiderEmote(z.afterEmote || "happy", 1.2, z.afterBubble || "WEB LANDED!");
      } else {
        spiderCtrl.x += (dx / dist) * zipStep;
        spiderCtrl.y += (dy / dist) * zipStep;
        spiderCtrl.vx = dx >= 0 ? Math.abs(spiderCtrl.vx) : -Math.abs(spiderCtrl.vx);
        z.silkLine.setAttribute("x1", String(Math.round(spiderCtrl.x + 44)));
        z.silkLine.setAttribute("y1", String(Math.round(spiderCtrl.y + 36)));
        z.silkGlow.setAttribute("x1", String(Math.round(spiderCtrl.x + 44)));
        z.silkGlow.setAttribute("y1", String(Math.round(spiderCtrl.y + 36)));
      }
      updateSpiderTransform();
      spiderCtrl.stepAccum += dt * 14;
      spiderCtrl.el.classList.toggle("step-b", Math.floor(spiderCtrl.stepAccum) % 2 === 1);
      requestAnimationFrame(tick);
      return;
    }

    if (spiderCtrl.emoteFor > 0) {
      spiderCtrl.emoteFor -= dt;
      if (spiderCtrl.emoteFor <= 0) {
        setSpiderEmote("", 0);
      }
    }

    if (spiderCtrl.pauseFor > 0) {
      spiderCtrl.pauseFor -= dt;
      requestAnimationFrame(tick);
      return;
    }

    if (spiderCtrl.boostFor > 0) {
      spiderCtrl.boostFor -= dt;
    }

    spiderCtrl.nextTurnIn -= dt;
    if (spiderCtrl.nextTurnIn <= 0) {
      spiderCtrl.nextTurnIn = 2.0 + Math.random() * 2.5;
      if (spiderCtrl.mode === "idle" && Math.random() < 0.35) {
        const contextEmote = pickContextIdleEmote();
        spiderCtrl.pauseFor = 2.2;
        setSpiderEmote(contextEmote.name, 2.2, contextEmote.bubble);
      } else {
        pickNewSpiderVelocity();
      }
    }

    const mult = spiderCtrl.boostFor > 0 ? 1.8 : spiderCtrl.mode === "scanning" ? 1.55 : 1.0;
    spiderCtrl.x += spiderCtrl.vx * mult * dt;
    spiderCtrl.y += spiderCtrl.vy * mult * dt;

    const minX = 10;
    const minY = 10;
    const maxX = Math.max(minX + 20, window.innerWidth - 96);
    const maxY = Math.max(minY + 20, window.innerHeight - 80);

    if (spiderCtrl.x >= maxX) {
      spiderCtrl.x = maxX;
      spiderCtrl.vx = -Math.abs(spiderCtrl.vx);
    } else if (spiderCtrl.x <= minX) {
      spiderCtrl.x = minX;
      spiderCtrl.vx = Math.abs(spiderCtrl.vx);
    }

    if (spiderCtrl.y >= maxY) {
      spiderCtrl.y = maxY;
      spiderCtrl.vy = -Math.abs(spiderCtrl.vy);
    } else if (spiderCtrl.y <= minY) {
      spiderCtrl.y = minY;
      spiderCtrl.vy = Math.abs(spiderCtrl.vy);
    }

    updateSpiderTransform();

    const stepRate = spiderCtrl.mode === "scanning" || spiderCtrl.boostFor > 0 ? 10 : 6;
    spiderCtrl.stepAccum += dt * stepRate;
    spiderCtrl.el.classList.toggle("step-b", Math.floor(spiderCtrl.stepAccum) % 2 === 1);

    requestAnimationFrame(tick);
  }

  requestAnimationFrame(tick);
}

updateAiFieldVisibility();
goToStep(1, { scroll: false });
startSpiderPatrol();
refreshHistoryCount();
