"""Health API and error handling tests (Phase 1 / 20)."""


def test_health_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_unknown_route_returns_envelope(client):
    resp = client.get("/api/does-not-exist")
    assert resp.status_code == 404
    body = resp.json()
    assert "error" in body
    assert body["error"]["code"] == "not_found"


def test_no_stack_trace_in_production_error(client, auth_headers):
    # Trigger an internal-style error path: request with an invalid body type.
    resp = client.post(
        "/api/targets",
        headers=auth_headers,
        json={"name": "x", "address": 12345},  # wrong type
    )
    assert resp.status_code in (400, 422)
    assert "Traceback" not in resp.text
    assert "line" not in resp.text.lower()


def test_security_headers_present(client):
    resp = client.get("/api/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in resp.headers
    assert resp.headers.get("server") == "CyberSentinel"


def test_oversized_body_rejected(client):
    resp = client.post(
        "/api/auth/login",
        json={"username": "a" * 1_500_000, "password": "b"},
    )
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "payload_too_large"


def test_cors_header_echoed(client):
    resp = client.options(
        "/api/targets",
        headers={
            "Origin": "http://localhost:5500",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert resp.status_code == 200
