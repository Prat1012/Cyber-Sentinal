/* Scan detail: overview, hosts/ports, findings, report generation. */
"use strict";

(function () {
  initShell();

  const params = new URLSearchParams(location.search);
  const scanId = params.get("id");

  if (!scanId) {
    location.replace("scan.html");
    return;
  }

  async function load() {
    try {
      const data = await API.get("/scans/" + scanId);
      render(data);
      // Refresh while a scan is still running.
      if (["QUEUED", "RUNNING"].includes(data.scan.status)) {
        setTimeout(load, 4000);
      }
    } catch (err) {
      $("detailTitle").textContent = "Scan not found";
      $("detailSubtitle").textContent = err.message;
      $("detailBody").innerHTML = '<div class="empty-state"><div class="icon">🔍</div><p>' + esc(err.message) + "</p></div>";
    }
  }

  function render(data) {
    const scan = data.scan;
    const summary = data.summary || {};
    const findings = summary.findings_by_severity || {};

    $("detailTitle").textContent = "Scan #" + scan.id;
    $("detailSubtitle").textContent = data.target_address ? "Target: " + data.target_address : "";

    const risk = scan.risk_score;
    const riskColorVal = riskColor(risk);

    let findingsHtml = "";
    if (summary.findings_count) {
      findingsHtml = `
        <div class="stat-grid" style="grid-template-columns:repeat(5,1fr)">
          ${["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => `
            <div class="stat-card sev-${sev.toLowerCase()}"><div class="stat-label">${sev}</div><div class="stat-value">${findings[sev] || 0}</div></div>`).join("")}
        </div>`;
    }

    const hostsRows = data.hosts.map((h) => `
      <tr>
        <td class="mono">${esc(h.ip_address)}</td>
        <td>${esc(h.hostname || "—")}</td>
        <td>${esc(h.status)}</td>
        <td>${esc(h.os_guess || "—")}</td>
      </tr>`).join("");

    const portRows = data.ports.map((p) => `
      <tr>
        <td class="mono">${esc(p.host_ip || "")}${p.host_ip ? ":" : ""}${p.port}</td>
        <td>${esc(p.protocol)}</td>
        <td>${esc(p.state)}</td>
        <td>${esc(p.service || "—")}</td>
        <td class="muted">${esc([p.product, p.version].filter(Boolean).join(" ") || "—")}</td>
      </tr>`).join("");

    $("detailBody").innerHTML = `
      <div class="grid-3">
        <div class="card">
          <div class="card-header"><h2>Overview</h2></div>
          <div class="card-body">
            <div class="kv"><span class="k">Target</span><span class="v mono">${esc(data.target_address || "—")}</span></div>
            <div class="kv"><span class="k">Status</span><span class="v">${statusBadge(scan.status)}</span></div>
            <div class="kv"><span class="k">Scan type</span><span class="v"><span class="pill">${esc(scan.scan_type)}</span> · ${esc(scan.port_range)}</span></div>
            <div class="kv"><span class="k">Engine</span><span class="v"><span class="pill">${esc(scan.scan_engine || "—")}</span></span></div>
            <div class="kv"><span class="k">Requested</span><span class="v">${fmtTime(scan.requested_at)}</span></div>
            <div class="kv"><span class="k">Started</span><span class="v">${fmtTime(scan.started_at)}</span></div>
            <div class="kv"><span class="k">Completed</span><span class="v">${fmtTime(scan.completed_at)}</span></div>
            <div class="kv"><span class="k">Duration</span><span class="v mono">${fmtDuration(scan.duration_seconds)}</span></div>
            ${scan.error_message ? '<div class="form-error" style="margin-top:10px">' + esc(scan.error_message) + "</div>" : ""}
          </div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Risk score</h2></div>
          <div class="card-body risk-gauge">
            <div class="risk-score" style="color:${riskColorVal}">${risk !== null && risk !== undefined ? risk.toFixed(1) : "—"}</div>
            <div class="muted" style="margin-top:6px">${riskLabel(risk)} · CVSS v3.1 scale</div>
            <div class="stat-grid" style="margin-top:18px;grid-template-columns:repeat(3,1fr)">
              <div class="stat-card sev-info"><div class="stat-label">Hosts</div><div class="stat-value" style="font-size:22px">${summary.hosts_count || 0}</div></div>
              <div class="stat-card sev-info"><div class="stat-label">Open ports</div><div class="stat-value" style="font-size:22px">${summary.open_ports_count || 0}</div></div>
              <div class="stat-card sev-info"><div class="stat-label">Findings</div><div class="stat-value" style="font-size:22px">${summary.findings_count || 0}</div></div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Actions</h2></div>
          <div class="card-body">
            <a class="btn btn-primary w-full" id="genReportBtn" href="#">📄 Generate PDF report</a>
            <a class="btn w-full mt-16" href="findings.html?scan_id=${scan.id}">🔎 View all findings</a>
            <button class="btn btn-danger w-full mt-16" id="deleteScanBtn" type="button">Delete scan</button>
            <div class="form-error" id="detailError"></div>
          </div>
        </div>
      </div>

      ${findingsHtml ? '<div style="margin-top:18px">' + findingsHtml + "</div>" : ""}

      ${data.technologies && data.technologies.length ? `
      <div class="section-title">Technologies</div>
      <div class="card"><div class="card-body">${data.technologies.map((t) => `<span class="pill" style="margin:2px 6px 2px 0">${esc(t)}</span>`).join("")}</div></div>
      ` : ""}

      <div class="section-title">Discovered hosts</div>
      <div class="card">
        <div class="table-wrap">
          <table>
            <thead><tr><th>IP address</th><th>Hostname</th><th>Status</th><th>OS guess</th></tr></thead>
            <tbody>${hostsRows || '<tr><td colspan="4"><div class="empty-state"><p>No hosts recorded.</p></div></td></tr>'}</tbody>
          </table>
        </div>
      </div>

      <div class="section-title">Open ports &amp; services</div>
      <div class="card">
        <div class="table-wrap">
          <table>
            <thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product / version</th></tr></thead>
            <tbody>${portRows || '<tr><td colspan="5"><div class="empty-state"><p>No open ports found.</p></div></td></tr>'}</tbody>
          </table>
        </div>
      </div>`;

    $("genReportBtn").addEventListener("click", async (e) => {
      e.preventDefault();
      const btn = $("genReportBtn");
      setLoading(btn, true, "Generating report…");
      try {
        const report = await API.post("/reports/scans/" + scan.id, {});
        toast("Report generated", "success");
        setTimeout(() => {
          window.open("/api/reports/" + report.id + "/download", "_blank");
        }, 300);
      } catch (err) {
        $("detailError").textContent = err.message;
      } finally {
        setLoading(btn, false);
      }
    });

    $("deleteScanBtn").addEventListener("click", async () => {
      if (!confirmAction("Delete scan #" + scan.id + " and all of its data?")) return;
      try {
        await API.del("/scans/" + scan.id);
        location.href = "scan.html";
      } catch (err) {
        $("detailError").textContent = err.message;
      }
    });
  }

  load();
})();
