"""Scan management API tests (Phase 12 / 20)."""


def _scan(client, headers, target_id, **kwargs):
    payload = {"target_id": target_id, **kwargs}
    return client.post("/api/scans", headers=headers, json=payload)


def test_create_scan_queued(client, auth_headers, created_target):
    resp = _scan(client, auth_headers, created_target["id"])
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "QUEUED"
    assert body["scan_type"] == "full"
    assert body["target_id"] == created_target["id"]


def test_create_scan_other_users_target_rejected(client):
    a = client.post("/api/auth/register", json={"username": "alice", "password": "password123"}).json()
    b = client.post("/api/auth/register", json={"username": "bob", "password": "password123"}).json()
    token_a = client.post("/api/auth/login", json={"username": "alice", "password": "password123"}).json()["access_token"]
    token_b = client.post("/api/auth/login", json={"username": "bob", "password": "password123"}).json()["access_token"]

    target = client.post("/api/targets", headers={"Authorization": f"Bearer {token_a}"},
                         json={"name": "t", "address": "127.0.0.1"}).json()
    resp = _scan(client, {"Authorization": f"Bearer {token_b}"}, target["id"])
    assert resp.status_code == 404


def test_scan_public_ip_rejected_by_default(client, auth_headers):
    target = client.post("/api/targets", headers=auth_headers,
                         json={"name": "public", "address": "8.8.8.8"}).json()
    resp = _scan(client, auth_headers, target["id"])
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


def test_scan_public_hostname_rejected_by_default(client, auth_headers):
    target = client.post("/api/targets", headers=auth_headers,
                         json={"name": "ext", "address": "example.com"}).json()
    resp = _scan(client, auth_headers, target["id"])
    # example.com does not resolve to a private address.
    assert resp.status_code == 403


def test_scan_invalid_scan_type_rejected(client, auth_headers, created_target):
    resp = _scan(client, auth_headers, created_target["id"], scan_type="nonsense")
    assert resp.status_code == 422


def test_scan_invalid_port_range_rejected(client, auth_headers, created_target):
    resp = _scan(client, auth_headers, created_target["id"], port_range="0-70000")
    assert resp.status_code == 422
    resp = _scan(client, auth_headers, created_target["id"], port_range="1-5000")
    assert resp.status_code == 422  # exceeds 1024 port limit


def test_list_scans_and_detail(client, auth_headers, created_target):
    created = _scan(client, auth_headers, created_target["id"]).json()
    listed = client.get("/api/scans", headers=auth_headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    detail = client.get(f"/api/scans/{created['id']}", headers=auth_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["target_address"] == "127.0.0.1"
    assert body["summary"]["hosts_count"] == 0
    assert body["hosts"] == []


def test_cancel_queued_scan(client, auth_headers, created_target):
    created = _scan(client, auth_headers, created_target["id"]).json()
    resp = client.post(f"/api/scans/{created['id']}/cancel", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "CANCELLED"


def test_delete_scan(client, auth_headers, created_target):
    created = _scan(client, auth_headers, created_target["id"]).json()
    resp = client.delete(f"/api/scans/{created['id']}", headers=auth_headers)
    assert resp.status_code == 204
    assert client.get(f"/api/scans/{created['id']}", headers=auth_headers).status_code == 404
