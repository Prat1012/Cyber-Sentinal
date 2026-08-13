"""Target management and validation tests (Phase 3 / 20)."""


def _create(client, headers, address, name="t"):
    return client.post("/api/targets", headers=headers, json={"name": name, "address": address})


def test_create_valid_ip(client, auth_headers):
    resp = _create(client, auth_headers, "127.0.0.1")
    assert resp.status_code == 201
    assert resp.json()["address_type"] == "ip"


def test_create_valid_hostname(client, auth_headers):
    resp = _create(client, auth_headers, "localhost")
    assert resp.status_code == 201
    assert resp.json()["address_type"] == "hostname"


def test_create_valid_private_ip(client, auth_headers):
    resp = _create(client, auth_headers, "192.168.1.10")
    assert resp.status_code == 201


def test_create_rejects_shell_injection(client, auth_headers):
    for evil in [
        "127.0.0.1; rm -rf /",
        "127.0.0.1 && whoami",
        "$(id)",
        "`cat /etc/passwd`",
        "localhost|cat",
        "http://127.0.0.1",
        "1.2.3.999",
        "not a hostname!",
        "host name",
        "",
        "a" * 300,
    ]:
        resp = _create(client, auth_headers, evil)
        assert resp.status_code in (400, 422), f"{evil!r} should be rejected: {resp.text}"


def test_create_duplicate_address_conflict(client, auth_headers):
    assert _create(client, auth_headers, "10.0.0.5").status_code == 201
    resp = _create(client, auth_headers, "10.0.0.5")
    assert resp.status_code == 409


def test_list_and_get_target(client, auth_headers):
    created = _create(client, auth_headers, "127.0.0.1").json()
    listed = client.get("/api/targets", headers=auth_headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    got = client.get(f"/api/targets/{created['id']}", headers=auth_headers)
    assert got.status_code == 200
    assert got.json()["address"] == "127.0.0.1"


def test_delete_target(client, auth_headers):
    created = _create(client, auth_headers, "127.0.0.1").json()
    resp = client.delete(f"/api/targets/{created['id']}", headers=auth_headers)
    assert resp.status_code == 204
    assert client.get("/api/targets", headers=auth_headers).json() == []


def test_ownership_isolation(client):
    # User A creates a target; user B must not see or touch it.
    a = client.post("/api/auth/register", json={"username": "alice", "password": "password123"}).json()
    b = client.post("/api/auth/register", json={"username": "bob", "password": "password123"}).json()
    token_a = client.post("/api/auth/login", json={"username": "alice", "password": "password123"}).json()["access_token"]
    token_b = client.post("/api/auth/login", json={"username": "bob", "password": "password123"}).json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    target = _create(client, headers_a, "127.0.0.2").json()

    assert client.get("/api/targets", headers=headers_b).json() == []
    assert client.get(f"/api/targets/{target['id']}", headers=headers_b).status_code == 404
    assert client.delete(f"/api/targets/{target['id']}", headers=headers_b).status_code == 404


def test_update_target(client, auth_headers):
    target = _create(client, auth_headers, "127.0.0.3").json()
    resp = client.patch(
        f"/api/targets/{target['id']}",
        headers=auth_headers,
        json={"description": "updated"},
    )
    assert resp.status_code == 200
    assert resp.json()["description"] == "updated"
