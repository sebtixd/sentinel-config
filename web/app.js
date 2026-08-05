/**
 * SENTINEL — Security Audit Dashboard Frontend Controller
 */

(function () {
  let currentRunData = null;
  let activeStatusFilter = "ALL";
  let activePollTimer = null;

  // DOM Elements
  const runHistorySelect = document.getElementById("runHistorySelect");
  const btnNewAudit = document.getElementById("btnNewAudit");
  const btnCompareRuns = document.getElementById("btnCompareRuns");
  const btnDownloadPdf = document.getElementById("btnDownloadPdf");
  const activeRunBanner = document.getElementById("activeRunBanner");
  const activeRunMsg = document.getElementById("activeRunMsg");

  // Metrics Elements
  const valCompliancePct = document.getElementById("valCompliancePct");
  const barCompliance = document.getElementById("barCompliance");
  const valTotalRules = document.getElementById("valTotalRules");
  const valRunTarget = document.getElementById("valRunTarget");
  const valPassCount = document.getElementById("valPassCount");
  const valFailCount = document.getElementById("valFailCount");
  const valInfoCount = document.getElementById("valInfoCount");
  const sectionsGrid = document.getElementById("sectionsGrid");

  // Table Elements
  const inputSearch = document.getElementById("inputSearch");
  const selectSectionFilter = document.getElementById("selectSectionFilter");
  const rulesTableBody = document.getElementById("rulesTableBody");

  // Modal Elements
  const modalNewAudit = document.getElementById("modalNewAudit");
  const formNewAudit = document.getElementById("formNewAudit");
  const btnCloseAuditModal = document.getElementById("btnCloseAuditModal");
  const btnCancelAuditModal = document.getElementById("btnCancelAuditModal");

  const modalCompare = document.getElementById("modalCompare");
  const btnCloseCompareModal = document.getElementById("btnCloseCompareModal");
  const compareRun1 = document.getElementById("compareRun1");
  const compareRun2 = document.getElementById("compareRun2");
  const btnExecuteCompare = document.getElementById("btnExecuteCompare");
  const compareSummaryBanner = document.getElementById("compareSummaryBanner");
  const compareTableBody = document.getElementById("compareTableBody");

  // Initialize App
  document.addEventListener("DOMContentLoaded", () => {
    fetchHistory();
    setupEventListeners();
  });

  function setupEventListeners() {
    runHistorySelect.addEventListener("change", (e) => {
      if (e.target.value) {
        loadRun(e.target.value);
      }
    });

    btnNewAudit.addEventListener("click", () => modalNewAudit.classList.remove("hidden"));
    btnCloseAuditModal.addEventListener("click", () => modalNewAudit.classList.add("hidden"));
    btnCancelAuditModal.addEventListener("click", () => modalNewAudit.classList.add("hidden"));

    btnCompareRuns.addEventListener("click", () => {
      modalCompare.classList.remove("hidden");
      populateCompareSelects();
    });
    btnCloseCompareModal.addEventListener("click", () => modalCompare.classList.add("hidden"));

    inputSearch.addEventListener("input", renderRulesTable);
    selectSectionFilter.addEventListener("change", renderRulesTable);

    // Status Pill Buttons
    document.querySelectorAll(".pill-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        document.querySelectorAll(".pill-btn").forEach((b) => b.classList.remove("active"));
        e.target.classList.add("active");
        activeStatusFilter = e.target.getAttribute("data-status");
        renderRulesTable();
      });
    });

    // Preset buttons in New Audit Modal
    document.querySelectorAll(".preset-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        document.getElementById("auditRules").value = e.target.getAttribute("data-scope");
      });
    });

    // PDF download
    btnDownloadPdf.addEventListener("click", () => {
      if (currentRunData && currentRunData.run_id) {
        window.open(`/api/audit/run/${currentRunData.run_id}/pdf`, "_blank");
      }
    });

    // Form submission
    formNewAudit.addEventListener("submit", handleAuditSubmit);
    btnExecuteCompare.addEventListener("click", handleCompareExecute);
  }

  async function fetchHistory() {
    try {
      const res = await fetch("/api/audit/runs");
      const runs = await res.json();

      runHistorySelect.innerHTML = "";
      if (runs.length === 0) {
        runHistorySelect.innerHTML = `<option value="">No Audit Runs Found</option>`;
        return;
      }

      runs.forEach((r, idx) => {
        const opt = document.createElement("option");
        opt.value = r.run_id;
        const dateStr = new Date(r.created_at).toLocaleString();
        const score = r.summary && r.summary.compliance_pct !== undefined ? `${r.summary.compliance_pct}%` : r.status;
        opt.textContent = `${r.hostname} (${r.target_os}) — ${dateStr} [${score}]`;
        runHistorySelect.appendChild(opt);
      });

      // Load first run by default if none active
      if (!currentRunData && runs.length > 0) {
        runHistorySelect.value = runs[0].run_id;
        loadRun(runs[0].run_id);
      }
    } catch (err) {
      console.error("Error fetching run history:", err);
    }
  }

  async function loadRun(runId) {
    if (activePollTimer) {
      clearInterval(activePollTimer);
      activePollTimer = null;
    }

    try {
      const res = await fetch(`/api/audit/run/${runId}`);
      if (!res.ok) return;

      const data = await res.json();
      currentRunData = data;

      if (data.status === "running") {
        activeRunBanner.classList.remove("hidden");
        activeRunBanner.style.backgroundColor = "rgba(59, 130, 246, 0.15)";
        activeRunBanner.style.borderColor = "var(--accent-blue)";
        activeRunMsg.innerHTML = `<strong>Audit in Progress:</strong> ${data.progress_message || "Audit in progress..."}`;
        activePollTimer = setInterval(() => pollRunStatus(runId), 3000);
      } else if (data.status === "failed") {
        activeRunBanner.classList.remove("hidden");
        activeRunBanner.style.backgroundColor = "rgba(244, 63, 94, 0.15)";
        activeRunBanner.style.borderColor = "var(--fail-color)";
        activeRunMsg.innerHTML = `<strong style="color: var(--fail-color)">Audit Failed:</strong> ${escapeHtml(data.error || "Unable to connect or complete audit run.")}`;
      } else {
        activeRunBanner.classList.add("hidden");
      }

      renderMetrics(data);
      renderSectionsGrid(data);
      renderRulesTable();
    } catch (err) {
      console.error("Error loading run:", err);
    }
  }

  async function pollRunStatus(runId) {
    try {
      const res = await fetch(`/api/audit/run/${runId}`);
      const data = await res.json();

      if (data.status !== "running") {
        clearInterval(activePollTimer);
        activePollTimer = null;
        if (data.status === "failed") {
          activeRunBanner.classList.remove("hidden");
          activeRunBanner.style.backgroundColor = "rgba(244, 63, 94, 0.15)";
          activeRunBanner.style.borderColor = "var(--fail-color)";
          activeRunMsg.innerHTML = `<strong style="color: var(--fail-color)">Audit Failed:</strong> ${escapeHtml(data.error || "Unable to connect or complete audit run.")}`;
        } else {
          activeRunBanner.classList.add("hidden");
        }
        fetchHistory();
      } else {
        activeRunMsg.textContent = data.progress_message || "Processing remote audit...";
      }

      currentRunData = data;
      renderMetrics(data);
      renderSectionsGrid(data);
      renderRulesTable();
    } catch (err) {
      console.error("Polling error:", err);
    }
  }

  function renderMetrics(data) {
    const sum = data.summary || {};
    const pct = sum.compliance_pct !== undefined ? sum.compliance_pct : 0;
    
    valCompliancePct.textContent = `${pct}%`;
    barCompliance.style.width = `${pct}%`;
    valTotalRules.textContent = sum.total_checked || 0;
    valRunTarget.textContent = `Host: ${data.hostname || 'N/A'} (${data.target_os || 'linux'})`;

    valPassCount.textContent = sum.pass_count || 0;
    valFailCount.textContent = sum.fail_count || 0;
    valInfoCount.textContent = (sum.info_count || 0) + (sum.unknown_count || 0);

    // Enable PDF download button only when run is completed
    if (btnDownloadPdf) {
      if (data.status === "completed") {
        btnDownloadPdf.disabled = false;
        btnDownloadPdf.title = "Download PDF Report";
      } else {
        btnDownloadPdf.disabled = true;
        btnDownloadPdf.title = data.status === "running" ? "PDF generates after audit completes" : "No PDF available";
      }
    }
  }

  function renderSectionsGrid(data) {
    sectionsGrid.innerHTML = "";
    const sections = (data.summary && data.summary.sections) || {};

    Object.keys(sections).sort().forEach((secKey) => {
      const sec = sections[secKey];
      const card = document.createElement("div");
      card.className = "sec-card";
      
      const pctColor = sec.compliance_pct >= 80 ? "text-pass" : (sec.compliance_pct >= 50 ? "text-info" : "text-fail");

      card.innerHTML = `
        <div class="sec-card-header">
          <span class="sec-card-title">Sec ${secKey} — ${sec.name}</span>
          <span class="sec-card-pct ${pctColor}">${sec.compliance_pct}%</span>
        </div>
        <div class="metric-bar-bg">
          <div class="metric-bar-fill" style="width: ${sec.compliance_pct}%; background-color: var(${sec.compliance_pct >= 80 ? '--pass-color' : (sec.compliance_pct >= 50 ? '--info-color' : '--fail-color')});"></div>
        </div>
        <div class="sec-card-counts">
          <span class="text-pass">✓ ${sec.pass} Pass</span>
          <span class="text-fail">✗ ${sec.fail} Fail</span>
          <span class="text-slate">Total: ${sec.total}</span>
        </div>
      `;
      sectionsGrid.appendChild(card);
    });
  }

  function renderRulesTable() {
    rulesTableBody.innerHTML = "";
    if (!currentRunData || !currentRunData.structured_rules || currentRunData.structured_rules.length === 0) {
      rulesTableBody.innerHTML = `<tr><td colspan="5" class="table-empty">No rules found for this audit run.</td></tr>`;
      return;
    }

    const searchQuery = inputSearch.value.toLowerCase().trim();
    const sectionFilter = selectSectionFilter.value;

    const filtered = currentRunData.structured_rules.filter((rule) => {
      // Search filter
      if (searchQuery) {
        const matchId = rule.rule_id.toLowerCase().includes(searchQuery);
        const matchTitle = rule.title.toLowerCase().includes(searchQuery);
        const matchEv = (rule.evidence || "").toLowerCase().includes(searchQuery);
        if (!matchId && !matchTitle && !matchEv) return false;
      }

      // Section filter
      if (sectionFilter !== "ALL" && rule.section_num !== sectionFilter) {
        return false;
      }

      // Status pill filter
      if (activeStatusFilter !== "ALL") {
        if (activeStatusFilter === "UNKNOWN" && (rule.status === "UNKNOWN" || rule.status === "INFORMATIONAL")) {
          return true;
        }
        if (rule.status !== activeStatusFilter) return false;
      }

      return true;
    });

    if (filtered.length === 0) {
      rulesTableBody.innerHTML = `<tr><td colspan="5" class="table-empty">No rules match the selected filters.</td></tr>`;
      return;
    }

    filtered.forEach((rule, idx) => {
      const tr = document.createElement("tr");
      const badgeClass = rule.status === "PASS" ? "badge-pass" : (rule.status === "FAIL" ? "badge-fail" : "badge-info");
      
      tr.innerHTML = `
        <td><code class="rule-id-code">${rule.rule_id}</code></td>
        <td><span class="badge ${badgeClass}">${rule.status}</span></td>
        <td><strong>${escapeHtml(rule.title)}</strong></td>
        <td><span class="text-slate">Sec ${rule.section}</span></td>
        <td>
          <button class="btn btn-secondary btn-sm toggle-ev-btn" data-idx="${idx}">Details ▾</button>
        </td>
      `;
      rulesTableBody.appendChild(tr);

      // Evidence detail row (hidden by default)
      const trEv = document.createElement("tr");
      trEv.className = "evidence-row hidden";
      trEv.id = `ev-row-${idx}`;
      trEv.innerHTML = `
        <td colspan="5">
          <div>
            <strong>Collected Evidence / Facts:</strong>
            <div class="evidence-box">${escapeHtml(rule.evidence || 'No specific evidence reported.')}</div>
            ${rule.recommendation && rule.status === 'FAIL' ? `<div class="rec-box"><strong>Remediation Recommendation:</strong> ${escapeHtml(rule.recommendation)}</div>` : ''}
          </div>
        </td>
      `;
      rulesTableBody.appendChild(trEv);
    });

    // Attach click handlers to Details buttons
    document.querySelectorAll(".toggle-ev-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const idx = e.target.getAttribute("data-idx");
        const evRow = document.getElementById(`ev-row-${idx}`);
        if (evRow) {
          evRow.classList.toggle("hidden");
          e.target.textContent = evRow.classList.contains("hidden") ? "Details ▾" : "Hide ▴";
        }
      });
    });
  }

  async function handleAuditSubmit(e) {
    e.preventDefault();
    const payload = {
      hostname: document.getElementById("auditHostname").value.trim(),
      port: parseInt(document.getElementById("auditPort").value) || null,
      username: document.getElementById("auditUsername").value.trim(),
      password: document.getElementById("auditPassword").value || null,
      key_filename: document.getElementById("auditKeyFile").value.trim() || null,
      target_os: document.getElementById("auditTargetOs").value,
      rules: document.getElementById("auditRules").value.trim() || null,
    };

    try {
      const res = await fetch("/api/audit/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json();
        alert(`Error triggering audit: ${err.detail || 'Unknown error'}`);
        return;
      }

      const result = await res.json();
      modalNewAudit.classList.add("hidden");
      await fetchHistory();
      runHistorySelect.value = result.run_id;
      loadRun(result.run_id);
    } catch (err) {
      alert(`Network error triggering audit: ${err.message}`);
    }
  }

  function populateCompareSelects() {
    const options = runHistorySelect.innerHTML;
    compareRun1.innerHTML = options;
    compareRun2.innerHTML = options;
    if (compareRun2.options.length > 1) {
      compareRun2.selectedIndex = 1;
    }
  }

  async function handleCompareExecute() {
    const r1 = compareRun1.value;
    const r2 = compareRun2.value;
    if (!r1 || !r2) return;

    try {
      const res = await fetch(`/api/audit/compare?run_id_1=${r1}&run_id_2=${r2}`);
      const data = await res.json();

      compareSummaryBanner.classList.remove("hidden");
      compareSummaryBanner.innerHTML = `
        <div><strong>Fixed Rules (FAIL → PASS):</strong> <span class="text-pass">${data.fixed_count}</span></div>
        <div><strong>Regressed Rules (PASS → FAIL):</strong> <span class="text-fail">${data.regressed_count}</span></div>
        <div><strong>Total Rules Compared:</strong> <span class="text-slate">${data.total_compared}</span></div>
      `;

      compareTableBody.innerHTML = "";
      data.comparisons.forEach((c) => {
        const tr = document.createElement("tr");
        let badgeStyle = "color: var(--text-muted)";
        if (c.diff_status === "FIXED") badgeStyle = "color: var(--pass-color); font-weight: bold;";
        if (c.diff_status === "REGRESSED") badgeStyle = "color: var(--fail-color); font-weight: bold;";

        tr.innerHTML = `
          <td><code class="rule-id-code">${c.rule_id}</code></td>
          <td>${escapeHtml(c.title)}</td>
          <td><span class="badge ${c.status_run_1 === 'PASS' ? 'badge-pass' : 'badge-fail'}">${c.status_run_1}</span></td>
          <td><span class="badge ${c.status_run_2 === 'PASS' ? 'badge-pass' : 'badge-fail'}">${c.status_run_2}</span></td>
          <td><span style="${badgeStyle}">${c.diff_status}</span></td>
        `;
        compareTableBody.appendChild(tr);
      });
    } catch (err) {
      console.error("Comparison error:", err);
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

})();
