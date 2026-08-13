/* Reports page: list, generate from a completed scan, download. */
"use strict";

(function () {
  initShell();

  const body = $("reportsBody");
  const genModal = $("reportModal");
  const scanSelect = $("reportScanSelect");

  $("genReportBtn").addEventListener("click", async () => {
    $("reportFormError").textContent = "";
    await loadCompletedScans();
    openModal("reportModal");
  });
  $("closeReportModal").addEventListener("click", () => closeModal("reportModal"));
  genModal.addEventListener("click", (e) => {
    if (e.target === genModal) closeModal("reportModal");
  });

  async function loadCompletedScans() {
    try {
      const scans = await API.get("/scans", { limit: 200 });
      const completed = scans.filter((s) => s.status === "COMPLETED");
      if (!completed.length) {
        scanSelect.innerHTML = '<option value="">No completed scans yet</option>';
        return;
      }
      scanSelect.innerHTML = completed.map((s) =>
        '<option value="' + s.id + '">Scan #' + s.id + " · " + esc(s.target_address || "?") + " · risk " +
        (s.risk_score !== null && s.risk_score !== undefined ? s.risk_score.toFixed(1) : "—") + "</option>"
      ).join("");
    } catch (err) {
      $("reportFormError").textContent = err.message;
    }
  }

  $("reportForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("reportSubmitBtn");
    $("reportFormError").textContent = "";
    if (!scanSelect.value) {
      $("reportFormError").textContent = "Select a completed scan.";
      return;
    }
    setLoading(btn, true, "Generating PDF…");
    try {
      const report = await API.post("/reports/scans/" + scanSelect.value, {});
      toast("Report generated", "success");
      closeModal("reportModal");
      load();
      downloadReport(report.id, "pdf");
    } catch (err) {
      $("reportFormError").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });

  async function downloadReport(reportId, format) {
    // Authenticated blob download (anchor links cannot send the Bearer token).
    try {
      const path = "/reports/" + reportId + (format === "pdf" ? "/download" : "/export");
      const params = format === "pdf" ? undefined : { format };
      const { blob, filename } = await API.download(path, params);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || ("CyberSentinel-Report-" + reportId + (format === "pdf" ? ".pdf" : "." + format));
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (err) {
      toast(err.message, "error");
    }
  }
  window.downloadReport = downloadReport;

  async function load() {
    try {
      const reports = await API.get("/reports");
      if (!reports.length) {
        body.innerHTML = '<tr><td colspan="7"><div class="empty-state"><div class="icon">📄</div><p>No reports yet. Generate a PDF from a completed scan.</p></div></td></tr>';
        return;
      }
      body.innerHTML = reports.map((r) => `
        <tr>
          <td class="mono">#${r.id}</td>
          <td class="mono">#${r.scan_id}</td>
          <td class="mono">${esc(r.filename)}</td>
          <td><span class="pill">${esc(r.file_format)}</span></td>
          <td class="mono">${r.size_bytes !== null && r.size_bytes !== undefined ? (r.size_bytes / 1024).toFixed(1) + " KB" : "—"}</td>
          <td>${fmtTime(r.created_at)}</td>
          <td style="white-space:nowrap">
            <button class="btn btn-sm btn-primary" data-dl="pdf" data-id="${r.id}" type="button">PDF</button>
            <button class="btn btn-sm btn-ghost" data-dl="json" data-id="${r.id}" type="button">JSON</button>
            <button class="btn btn-sm btn-ghost" data-dl="csv" data-id="${r.id}" type="button">CSV</button>
            <button class="btn btn-sm btn-danger" data-del="${r.id}" type="button">Delete</button>
          </td>
        </tr>`).join("");

      body.querySelectorAll("[data-dl]").forEach((btn) => {
        btn.addEventListener("click", () => downloadReport(btn.dataset.id, btn.dataset.dl));
      });

      body.querySelectorAll("[data-del]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (!confirmAction("Delete this report?")) return;
          try {
            await API.del("/reports/" + btn.dataset.del);
            toast("Report deleted", "success");
            load();
          } catch (err) {
            toast(err.message, "error");
          }
        });
      });
    } catch (err) {
      body.innerHTML = '<tr><td colspan="7"><div class="empty-state"><p>Failed to load reports: ' + esc(err.message) + "</p></div></td></tr>";
    }
  }

  load();
})();
