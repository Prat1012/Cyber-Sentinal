/* CyberSentinel API client.
 * - attaches the Bearer token from localStorage
 * - redirects to the login page on 401
 * - normalizes error responses into Error objects
 */
"use strict";

const API = (() => {
  const TOKEN_KEY = "cs_token";
  const USER_KEY = "cs_user";

  function token() {
    return localStorage.getItem(TOKEN_KEY);
  }
  function setToken(t) {
    localStorage.setItem(TOKEN_KEY, t);
  }
  function setUser(user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }
  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || "null");
    } catch (e) {
      return null;
    }
  }
  function clearAuth() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }

  function isLoginPage() {
    const p = location.pathname.split("/").pop() || "index.html";
    return p === "index.html" || p === "" || p === "/";
  }

  async function request(path, { method = "GET", body, params } = {}) {
    let url = "/api" + path;
    if (params) {
      const qs = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "") qs.set(k, v);
      });
      const s = qs.toString();
      if (s) url += "?" + s;
    }

    const headers = { "Content-Type": "application/json" };
    const t = token();
    if (t) headers["Authorization"] = "Bearer " + t;

    let resp;
    try {
      resp = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
    } catch (e) {
      throw new Error("Network error - is the CyberSentinel server running?");
    }

    if (resp.status === 401) {
      clearAuth();
      if (!isLoginPage()) location.replace("index.html");
      throw new Error("Not authenticated.");
    }
    if (resp.status === 204) return null;

    let data = {};
    try {
      data = await resp.json();
    } catch (e) {
      data = {};
    }

    if (!resp.ok) {
      const detail = (data.error && data.error.detail) || data.detail || "Request failed (" + resp.status + ")";
      const message = typeof detail === "string" ? detail : JSON.stringify(detail);
      const err = new Error(message);
      err.status = resp.status;
      err.code = data.error && data.error.code;
      throw err;
    }
    return data;
  }

  async function download(path, params) {
    // Authenticated download (blob) - anchor links cannot carry the Bearer token.
    let url = "/api" + path;
    if (params) {
      const qs = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "") qs.set(k, v);
      });
      const s = qs.toString();
      if (s) url += "?" + s;
    }
    const headers = {};
    const t = token();
    if (t) headers["Authorization"] = "Bearer " + t;

    let resp;
    try {
      resp = await fetch(url, { method: "GET", headers });
    } catch (e) {
      throw new Error("Network error - is the CyberSentinel server running?");
    }
    if (resp.status === 401) {
      clearAuth();
      if (!isLoginPage()) location.replace("index.html");
      throw new Error("Not authenticated.");
    }
    if (!resp.ok) {
      let data = {};
      try {
        data = await resp.json();
      } catch (e) {
        data = {};
      }
      const detail = (data.error && data.error.detail) || data.detail || "Download failed (" + resp.status + ")";
      const message = typeof detail === "string" ? detail : JSON.stringify(detail);
      const err = new Error(message);
      err.status = resp.status;
      err.code = data.error && data.error.code;
      throw err;
    }
    const blob = await resp.blob();
    let filename = "";
    const m = (resp.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
    if (m) filename = m[1];
    return { blob, filename };
  }

  return {
    token,
    setToken,
    setUser,
    getUser,
    clearAuth,
    get: (p, params) => request(p, { params }),
    post: (p, body) => request(p, { method: "POST", body }),
    patch: (p, body) => request(p, { method: "PATCH", body }),
    del: (p) => request(p, { method: "DELETE" }),
    download,
  };
})();
