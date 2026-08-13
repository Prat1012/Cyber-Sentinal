/* Targets page: list, add, delete. */
"use strict";

(function () {
  initShell();

  const body = $("targetsBody");
  const modal = $("targetModal");
  const form = $("targetForm");

  $("addTargetBtn").addEventListener("click", () => {
    form.reset();
    $("targetFormError").textContent = "";
    openModal("targetModal");
  });
  $("closeTargetModal").addEventListener("click", () => closeModal("targetModal"));
  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeModal("targetModal");
  });

  async function load() {
    try {
      const targets = await API.get("/targets");
      if (!targets.length) {
        body.innerHTML = '<tr><td colspan="7"><div class="empty-state"><div class="icon">🎯</div><p>No targets registered yet. Add your first authorized lab target.</p></div></td></tr>';
        return;
      }
      body.innerHTML = targets.map((t) => `
        <tr>
          <td class="mono">#${t.id}</td>
          <td><strong>${esc(t.name)}</strong></td>
          <td><span class="mono">${esc(t.address)}</span></td>
          <td><span class="pill">${esc(t.address_type)}</span></td>
          <td class="muted">${esc(t.description || "—")}</td>
          <td>${fmtTime(t.created_at)}</td>
          <td>
            <a class="btn btn-sm btn-ghost" href="scan.html?target=${t.id}">Scan</a>
            <button class="btn btn-sm btn-danger" data-delete="${t.id}" data-name="${esc(t.address)}" type="button">Delete</button>
          </td>
        </tr>`).join("");

      body.querySelectorAll("[data-delete]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.dataset.delete;
          const addr = btn.dataset.name;
          if (!confirmAction("Delete target " + addr + "? This removes its scans and findings.")) return;
          try {
            await API.del("/targets/" + id);
            toast("Target deleted", "success");
            load();
          } catch (err) {
            toast(err.message, "error");
          }
        });
      });
    } catch (err) {
      body.innerHTML = '<tr><td colspan="7"><div class="empty-state"><p>Failed to load targets: ' + esc(err.message) + "</p></div></td></tr>";
    }
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("targetSubmitBtn");
    setLoading(btn, true, "Saving…");
    $("targetFormError").textContent = "";
    try {
      await API.post("/targets", {
        name: $("targetName").value.trim(),
        address: $("targetAddress").value.trim(),
        description: $("targetDescription").value.trim() || null,
      });
      toast("Target added", "success");
      closeModal("targetModal");
      load();
    } catch (err) {
      $("targetFormError").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });

  load();
})();
