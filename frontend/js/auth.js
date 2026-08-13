/* Login / registration page logic. */
"use strict";

(function () {
  // Already signed in? Go to the dashboard.
  if (API.token()) {
    location.replace("dashboard.html");
    return;
  }

  const loginForm = $("loginForm");
  const registerForm = $("registerForm");
  const tabLogin = $("tabLogin");
  const tabRegister = $("tabRegister");

  function switchTab(register) {
    loginForm.hidden = register;
    registerForm.hidden = !register;
    tabLogin.classList.toggle("active", !register);
    tabRegister.classList.toggle("active", register);
  }

  tabLogin.addEventListener("click", () => switchTab(false));
  tabRegister.addEventListener("click", () => switchTab(true));

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("loginBtn");
    setLoading(btn, true, "Signing in…");
    $("loginError").textContent = "";
    try {
      const data = await API.post("/auth/login", {
        username: $("loginUsername").value.trim(),
        password: $("loginPassword").value,
      });
      API.setToken(data.access_token);
      API.setUser({ username: $("loginUsername").value.trim() });
      location.href = "dashboard.html";
    } catch (err) {
      $("loginError").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });

  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("registerBtn");
    $("registerError").textContent = "";
    if ($("regPassword").value !== $("regPassword2").value) {
      $("registerError").textContent = "Passwords do not match.";
      return;
    }
    setLoading(btn, true, "Creating account…");
    try {
      const user = await API.post("/auth/register", {
        username: $("regUsername").value.trim(),
        email: $("regEmail").value.trim() || null,
        password: $("regPassword").value,
      });
      // Auto sign-in after registration.
      const data = await API.post("/auth/login", {
        username: user.username,
        password: $("regPassword").value,
      });
      API.setToken(data.access_token);
      API.setUser({ username: user.username });
      location.href = "dashboard.html";
    } catch (err) {
      $("registerError").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });
})();
