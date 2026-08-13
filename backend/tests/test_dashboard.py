"""Dashboard aggregation tests (Phase 13 / 20)."""


def test_empty_dashboard(client, auth_headers):
    resp = client.get("/api/dashboard/summary", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_scans"] == 0
    assert body["total_targets"] == 0
    assert body["open_findings"] == 0
    assert set(body["findings_by_severity"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_dashboard_counts_targets_and_scans(client, auth_headers, created_target):
    client.post("/api/scans", headers=auth_headers, json={"target_id": created_target["id"]})
    client.post("/api/scans", headers=auth_headers, json={"target_id": created_target["id"]})

    resp = client.get("/api/dashboard/summary", headers=auth_headers)
    body = resp.json()
    assert body["total_targets"] == 1
    assert body["total_scans"] == 2
    assert body["scans_by_status"]["QUEUED"] == 2
    assert body["risk_distribution"]["none"] == 0  # no completed scans yet
    assert len(body["recent_scans"]) == 2


def test_dashboard_ownership_scope(client):
    a = client.post("/api/auth/register", json={"username": "alice", "password": "password123"}).json()
    b = client.post("/api/auth/register", json={"username": "bob", "password": "password123"}).json()
    token_a = client.post("/api/auth/login", json={"username": "alice", "password": "password123"}).json()["access_token"]
    token_b = client.post("/api/auth/login", json={"username": "bob", "password": "password123"}).json()["access_token"]

    client.post("/api/targets", headers={"Authorization": f"Bearer {token_a}"},
                json={"name": "t", "address": "127.0.0.1"})
    resp_b = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {token_b}"})
    assert resp_b.json()["total_targets"] == 0
