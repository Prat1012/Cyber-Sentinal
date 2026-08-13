/* Dashboard logic: stats, charts, recent scans. */
"use strict";

(function () {
  initShell();

  const SEV_COLORS = {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    MEDIUM: "#eab308",
    LOW: "#38bdf8",
    INFO: "#64748b",
  };

  let charts = {};

  function renderStats(data) {
    $("statScans").textContent = data.total_scans;
    $("statTargets").textContent = data.total_targets;
    $("statOpen").textContent = data.open_findings;
    $("statCritical").textContent = data.findings_by_severity.CRITICAL || 0;
    $("statHigh").textContent = data.findings_by_severity.HIGH || 0;
    $("statMedium").textContent = data.findings_by_severity.MEDIUM || 0;
    $("statLow").textContent = data.findings_by_severity.LOW || 0;
    const running = data.scans_by_status.RUNNING || 0;
    const queued = data.scans_by_status.QUEUED || 0;
    $("statScansNote").textContent = running + queued > 0
      ? running + " running · " + queued + " queued"
      : "No scans in progress";
  }

  function renderSeverityChart(data) {
    const sev = data.findings_by_severity || {};
    const labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    const values = labels.map((l) => sev[l] || 0);
    $("sevTotal").textContent = values.reduce((a, b) => a + b, 0) + " open findings";

    const ctx = $("chartSeverity").getContext("2d");
    if (charts.severity) charts.severity.destroy();
    charts.severity = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{ data: values, backgroundColor: labels.map((l) => SEV_COLORS[l]), borderColor: "#0d1526", borderWidth: 2 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "right", labels: { color: "#8296b8", boxWidth: 10 } },
          tooltip: { backgroundColor: "#101b31", titleColor: "#dbe6f5", bodyColor: "#dbe6f5" },
        },
      },
    });
  }

  function renderRiskChart(data) {
    const dist = data.risk_distribution || {};
    const labels = ["None", "Low", "Medium", "High", "Critical"];
    const keys = ["none", "low", "medium", "high", "critical"];
    const values = keys.map((k) => dist[k] || 0);
    const colors = ["#64748b", "#38bdf8", "#eab308", "#f97316", "#ef4444"];

    const ctx = $("chartRisk").getContext("2d");
    if (charts.risk) charts.risk.destroy();
    charts.risk = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{ label: "Scans", data: values, backgroundColor: colors, borderRadius: 6 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: "#8296b8" }, grid: { color: "rgba(28,42,71,0.4)" } },
          y: { beginAtZero: true, ticks: { color: "#8296b8", stepSize: 1 }, grid: { color: "rgba(28,42,71,0.4)" } },
        },
        plugins: { legend: { display: false }, tooltip: { backgroundColor: "#101b31" } },
      },
    });
  }

  function renderRecentScans(data) {
    const body = $("recentScansBody");
    const scans = data.recent_scans || [];
    if (!scans.length) {
      body.innerHTML = '<tr><td colspan="8"><div class="empty-state"><div class="icon">🛰️</div><p>No scans yet. Start your first assessment from the New Scan page.</p></div></td></tr>';
      return;
    }
    body.innerHTML = scans.map((s) => `
      <tr>
        <td class="mono">#${s.id}</td>
        <td><span class="mono">${esc(s.target_address || "—")}</span><div class="muted">${esc(s.target_name || "")}</div></td>
        <td><span class="pill">${esc(s.scan_type)}</span></td>
        <td>${statusBadge(s.status)}</td>
        <td class="mono" style="color:${riskColor(s.risk_score)}">${s.risk_score !== null && s.risk_score !== undefined ? s.risk_score.toFixed(1) : "—"} <span class="muted">${riskLabel(s.risk_score)}</span></td>
        <td>${fmtTime(s.requested_at)}</td>
        <td class="mono">${fmtDuration(s.duration_seconds)}</td>
        <td><a class="btn btn-sm btn-ghost" href="scan-detail.html?id=${s.id}">View</a></td>
      </tr>`).join("");
  }

  async function load() {
    try {
      const data = await API.get("/dashboard/summary");
      $("pageSubtitle").textContent = "Overview of assessments for " + (API.getUser() || {}).username || "";
      renderStats(data);
      renderSeverityChart(data);
      renderRiskChart(data);
      renderRecentScans(data);
    } catch (err) {
      $("pageSubtitle").textContent = err.message;
      $("recentScansBody").innerHTML = '<tr><td colspan="8"><div class="empty-state"><p>Failed to load dashboard: ' + esc(err.message) + "</p></div></td></tr>";
    }
  }

  load();
  // Auto-refresh so running scans appear without manual reloads.
  setInterval(load, 8000);
})();
