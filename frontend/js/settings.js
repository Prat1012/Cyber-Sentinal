/* Settings page: profile, platform info, safety notice. */
"use strict";

(function () {
  initShell();

  async function loadProfile() {
    try {
      const user = await API.get("/auth/me");
      $("profileUsername").textContent = user.username;
      $("profileEmail").textContent = user.email || "—";
      $("profileCreated").textContent = fmtTime(user.created_at);
      $("profileId").textContent = "#" + user.id;
    } catch (err) {
      $("profileBody").innerHTML = '<p class="muted">' + esc(err.message) + "</p>";
    }
  }

  loadProfile();
})();
