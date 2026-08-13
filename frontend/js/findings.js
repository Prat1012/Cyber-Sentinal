/* Findings page: filters, table, detail modal, status updates. */
"use strict";

(function () {
  initShell();

  const body = $("findingsBody");
  let current = null; // currently selected finding

  /* Only allow safe http(s) link targets (blocks javascript: URIs). */
function safeUrl(url) {
  try {
    const parsed = new URL(url, location.origin);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") return esc(url);
  } catch (e) {
    /* fall through */
  }
  return "#";
}

function currentParams() {
    const params = {};
    if ($("filterSeverity").value) params.severity = $("filterSeverity").value;
    if ($("filterStatus").value) params.status = $("filterStatus").value;
    if ($("filterCategory").value) params.category = $("filterCategory").value;
    if ($("filterHost").value.trim()) params.host = $("filterHost").value.trim();
    const q = new URLSearchParams(location.search);
    if (q.get("scan_id")) params.scan_id = q.get("scan_id");
    params.limit = 200;
    return params;
  }

  async function load() {
    try {
      const data = await API.get("/findings", currentParams());
      $("findingsCount").textContent = data.total + " finding(s)";
      $("findingsSubtitle").textContent = "Unified vulnerability findings" + (currentParams().scan_id ? " · scan #" + currentParams().scan_id : "");
      if (!data.items.length) {
        body.innerHTML = '<tr><td colspan="8"><div class="empty-state"><div class="icon">🛡️</div><p>No findings match the current filters.</p></div></td></tr>';
        return;
      }
      body.innerHTML = data.items.map((f) => `
        <tr data-id="${f.id}" style="cursor:pointer">
          <td>${severityBadge(f.severity)}</td>
          <td><strong>${esc(f.title)}</strong><div class="muted">${esc(f.category)}</div></td>
          <td class="mono">${f.cvss_score !== null && f.cvss_score !== undefined ? f.cvss_score.toFixed(1) : "—"}${f.cvss_vector ? '<div class="muted" style="font-size:10px">' + esc(f.cvss_vector.replace("CVSS:3.1/", "")) + "</div>" : ""}</td>
          <td class="mono">${esc(f.target_address || "—")}</td>
          <td class="mono muted">${esc(f.host_ip || f.affected_component || "—")}</td>
          <td>${statusBadge(f.status)}</td>
          <td class="muted">${fmtTime(f.created_at)}</td>
          <td><button class="btn btn-sm btn-ghost" data-view="${f.id}" type="button">Detail</button></td>
        </tr>`).join("");

      body.querySelectorAll("[data-view]").forEach((btn) => {
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          const f = data.items.find((x) => x.id === parseInt(btn.dataset.view, 10));
          if (f) openFinding(f);
        });
      });
      body.querySelectorAll("tr[data-id]").forEach((row) => {
        row.addEventListener("click", () => {
          const f = data.items.find((x) => x.id === parseInt(row.dataset.id, 10));
          if (f) openFinding(f);
        });
      });
    } catch (err) {
      body.innerHTML = '<tr><td colspan="8"><div class="empty-state"><p>Failed to load findings: ' + esc(err.message) + "</p></div></td></tr>";
    }
  }

  function openFinding(f) {
    current = f;
    $("findingModalTitle").textContent = "Finding #" + f.id;
    $("statusSelect").value = f.status;
    $("findingModalBody").innerHTML = `
      <div class="flex-between mb-16">
        ${severityBadge(f.severity)}
        <span class="pill">${esc(f.category)}</span>
      </div>
      <div class="detail-block">
        <h4>Description</h4>
        <div class="content">${esc(f.description)}</div>
      </div>
      <div class="grid-2" style="grid-template-columns:1fr 1fr">
        <div class="detail-block">
          <h4>Affected asset</h4>
          <div class="content mono">${esc(f.target_address || "—")}</div>
        </div>
        <div class="detail-block">
          <h4>Affected component</h4>
          <div class="content mono">${esc(f.affected_component || "—")}</div>
        </div>
      </div>
      ${f.cvss_score !== null && f.cvss_score !== undefined ? `
      <div class="detail-block">
        <h4>CVSS score (v3.1)</h4>
        <div class="content mono">${f.cvss_score.toFixed(1)} ${f.cvss_vector ? "· " + esc(f.cvss_vector) : ""}</div>
      </div>` : ""}
      ${f.evidence ? `
      <div class="detail-block">
        <h4>Evidence</h4>
        <div class="evidence-box">${esc(f.evidence)}</div>
      </div>` : ""}
      ${f.remediation ? `
      <div class="detail-block">
        <h4>Remediation</h4>
        <div class="content">${esc(f.remediation)}</div>
      </div>` : ""}
      ${f.reference ? `
      <div class="detail-block">
        <h4>Reference</h4>
        <div class="content"><a href="${safeUrl(f.reference)}" target="_blank" rel="noopener">${esc(f.reference)}</a></div>
      </div>` : ""}`;
    openModal("findingModal");
  }

  $("closeFindingModal").addEventListener("click", () => closeModal("findingModal"));
  $("findingModal").addEventListener("click", (e) => {
    if (e.target === $("findingModal")) closeModal("findingModal");
  });

  $("statusSaveBtn").addEventListener("click", async () => {
    if (!current) return;
    const btn = $("statusSaveBtn");
    setLoading(btn, true, "Updating…");
    try {
      await API.patch("/findings/" + current.id + "/status", { status: $("statusSelect").value });
      toast("Finding status updated", "success");
      closeModal("findingModal");
      load();
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setLoading(btn, false);
    }
  });

  $("filterApply").addEventListener("click", load);
  $("filterReset").addEventListener("click", () => {
    ["filterSeverity", "filterStatus", "filterCategory", "filterHost"].forEach((id) => {
      $(id).value = "";
    });
    const q = new URLSearchParams(location.search);
    q.delete("scan_id");
    history.replaceState(null, "", "findings.html" + (q.toString() ? "?" + q.toString() : ""));
    load();
  });
  ["filterSeverity", "filterStatus", "filterCategory"].forEach((id) => {
    $(id).addEventListener("change", load);
  });
  $("filterHost").addEventListener("keydown", (e) => {
    if (e.key === "Enter") load();
  });

  load();
})();
