/* Scan page: launch scans and list history with live status. */
"use strict";

(function () {
  initShell();

  const body = $("scansBody");
  const form = $("scanForm");
  const TERMINAL = ["COMPLETED", "FAILED", "CANCELLED"];

  async function loadTargets(preferredId) {
    try {
      const targets = await API.get("/targets");
      const select = $("scanTarget");
      if (!targets.length) {
        select.innerHTML = '<option value="">No targets — add one first</option>';
        $("scanFormError").textContent = "You need at least one registered target.";
        return;
      }
      select.innerHTML = targets.map((t) =>
        '<option value="' + t.id + '"' + (String(t.id) === String(preferredId) ? " selected" : "") + ">" +
        esc(t.name) + " (" + esc(t.address) + ")</option>"
      ).join("");
    } catch (err) {
      $("scanFormError").textContent = err.message;
    }
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("scanSubmitBtn");
    $("scanFormError").textContent = "";
    setLoading(btn, true, "Queuing scan…");
    try {
      const scan = await API.post("/scans", {
        target_id: parseInt($("scanTarget").value, 10),
        scan_type: $("scanType").value,
        port_range: $("scanPorts").value,
      });
      toast("Scan #" + scan.id + " queued", "success");
      load();
    } catch (err) {
      $("scanFormError").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });

  function renderRows(scans) {
    if (!scans.length) {
      body.innerHTML = '<tr><td colspan="8"><div class="empty-state"><div class="icon">🛰️</div><p>No scans yet. Configure and launch your first assessment.</p></div></td></tr>';
      return;
    }
    body.innerHTML = scans.map((s) => `
      <tr>
        <td class="mono">#${s.id}</td>
        <td><span class="mono">${esc(s.target_address || "—")}</span></td>
        <td><span class="pill">${esc(s.scan_type)}</span> <span class="muted">${esc(s.port_range)}</span></td>
        <td>${statusBadge(s.status)}${s.error_message ? '<div class="muted" title="' + esc(s.error_message) + '">⚠ error</div>' : ""}</td>
        <td class="mono" style="color:${riskColor(s.risk_score)}">${s.risk_score !== null && s.risk_score !== undefined ? s.risk_score.toFixed(1) : "—"}</td>
        <td><span class="pill">${esc(s.scan_engine || "—")}</span></td>
        <td>${fmtTime(s.requested_at)}</td>
        <td style="white-space:nowrap">
          <a class="btn btn-sm btn-ghost" href="scan-detail.html?id=${s.id}">View</a>
          ${s.status === "RUNNING" || s.status === "QUEUED" ? `<button class="btn btn-sm btn-ghost" data-cancel="${s.id}" type="button">Cancel</button>` : ""}
          <button class="btn btn-sm btn-danger" data-del="${s.id}" type="button">Delete</button>
        </td>
      </tr>`).join("");

    body.querySelectorAll("[data-cancel]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await API.post("/scans/" + btn.dataset.cancel + "/cancel");
          toast("Scan cancellation requested", "success");
          load();
        } catch (err) {
          toast(err.message, "error");
        }
      });
    });
    body.querySelectorAll("[data-del]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirmAction("Delete scan #" + btn.dataset.del + " and its findings?")) return;
        try {
          await API.del("/scans/" + btn.dataset.del);
          toast("Scan deleted", "success");
          load();
        } catch (err) {
          toast(err.message, "error");
        }
      });
    });
  }

  async function load() {
    try {
      const scans = await API.get("/scans");
      $("scanCount").textContent = scans.length + " scan(s)";
      renderRows(scans);
      const active = scans.some((s) => !TERMINAL.includes(s.status));
      clearTimeout(load.timer);
      if (active) load.timer = setTimeout(load, 4000);
    } catch (err) {
      body.innerHTML = '<tr><td colspan="8"><div class="empty-state"><p>Failed to load scans: ' + esc(err.message) + "</p></div></td></tr>";
    }
  }

  // Pre-select a target when arriving from the targets page.
  const params = new URLSearchParams(location.search);
  const preferredTarget = params.get("target");
  loadTargets(preferredTarget).then(load);
})();
