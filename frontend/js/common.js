/* Shared helpers: XSS-safe rendering, formatting, navigation, toasts. */
"use strict";

function $(id) {
  return document.getElementById(id);
}

/* Always render untrusted content through esc() to prevent XSS. */
function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function fmtDuration(sec) {
  if (sec === null || sec === undefined) return "—";
  if (sec < 60) return sec.toFixed(1) + "s";
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return m + "m " + s + "s";
}

function severityBadge(sev) {
  const s = (sev || "INFO").toLowerCase();
  return '<span class="badge badge-' + s + '">' + esc(sev) + "</span>";
}

function statusBadge(status) {
  const s = (status || "").toLowerCase();
  return '<span class="badge badge-' + s + '">' + esc(status || "—") + "</span>";
}

function riskLabel(score) {
  if (score === null || score === undefined) return "—";
  if (score <= 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}

function riskColor(score) {
  if (score <= 0) return "var(--info)";
  if (score < 4) return "var(--low)";
  if (score < 7) return "var(--medium)";
  if (score < 9) return "var(--high)";
  return "var(--critical)";
}

function toast(message, type) {
  let wrap = document.querySelector(".toast-wrap");
  if (!wrap) {
    wrap = document.createElement("div");
    wrap.className = "toast-wrap";
    document.body.appendChild(wrap);
  }
  const t = document.createElement("div");
  t.className = "toast" + (type ? " " + type : "");
  t.textContent = message;
  wrap.appendChild(t);
  setTimeout(() => {
    t.style.opacity = "0";
    t.style.transition = "opacity 0.3s";
    setTimeout(() => t.remove(), 320);
  }, 4200);
}

function requireAuth() {
  if (!API.token()) {
    location.replace("index.html");
  }
}

function renderUserChip() {
  const user = API.getUser();
  const nameEl = $("userName");
  if (nameEl) nameEl.textContent = user && user.username ? user.username : "user";
  const avatar = $("userAvatar");
  if (avatar && user && user.username) {
    avatar.textContent = user.username.charAt(0).toUpperCase();
  }
}

function setActiveNav() {
  const page = (location.pathname.split("/").pop() || "dashboard.html").toLowerCase();
  document.querySelectorAll(".nav-link").forEach((link) => {
    const href = (link.getAttribute("href") || "").toLowerCase();
    link.classList.toggle("active", href === page);
  });
}

function initShell() {
  requireAuth();
  renderUserChip();
  setActiveNav();
  const logout = $("logoutBtn");
  if (logout) {
    logout.addEventListener("click", () => {
      API.clearAuth();
      location.href = "index.html";
    });
  }
}

function openModal(id) {
  const m = $(id);
  if (m) m.classList.add("show");
}

function closeModal(id) {
  const m = $(id);
  if (m) m.classList.remove("show");
}

function confirmAction(message) {
  return window.confirm(message);
}

/* Toggle button loading state. */
function setLoading(btn, loading, text) {
  if (!btn) return;
  if (loading) {
    btn.dataset.orig = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="margin-right:6px"></span>' + (text || "Working…");
  } else {
    btn.disabled = false;
    if (btn.dataset.orig) btn.innerHTML = btn.dataset.orig;
  }
}

/* Escape function exposed for inline usage. */
window.esc = esc;
window.fmtTime = fmtTime;
window.fmtDuration = fmtDuration;
window.severityBadge = severityBadge;
window.statusBadge = statusBadge;
window.riskLabel = riskLabel;
window.riskColor = riskColor;
