"""Authentication tests (Phase 19 / 20)."""

import bcrypt

from app.database import SessionLocal
from app.models.user import User
from app.utils.security import decode_access_token

REGISTER = {"username": "alice", "password": "supersecret123", "email": "alice@example.com"}


def test_register_creates_user(client):
    resp = client.post("/api/auth/register", json=REGISTER)
    assert resp.status_code == 201
    assert resp.json()["username"] == "alice"
    # Never store plaintext passwords.
    with SessionLocal() as db:
        user = db.query(User).filter_by(username="alice").first()
        assert user is not None
        assert user.hashed_password != "supersecret123"
        assert bcrypt.checkpw(b"supersecret123", user.hashed_password.encode())


def test_register_weak_password_rejected(client):
    resp = client.post("/api/auth/register", json={"username": "bob", "password": "short"})
    assert resp.status_code == 422


def test_register_duplicate_username(client):
    assert client.post("/api/auth/register", json=REGISTER).status_code == 201
    resp = client.post("/api/auth/register", json=REGISTER)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "conflict"


def test_register_invalid_username_rejected(client):
    resp = client.post("/api/auth/register", json={"username": "bad user!", "password": "supersecret123"})
    assert resp.status_code == 400


def test_login_success_and_jwt(client):
    client.post("/api/auth/register", json=REGISTER)
    resp = client.post("/api/auth/login", json={"username": "alice", "password": "supersecret123"})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    assert resp.json()["token_type"] == "bearer"
    payload = decode_access_token(token)
    assert payload["sub"] == "1"


def test_login_wrong_password(client):
    client.post("/api/auth/register", json=REGISTER)
    resp = client.post("/api/auth/login", json={"username": "alice", "password": "wrongpass1"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


def test_login_unknown_user(client):
    resp = client.post("/api/auth/login", json={"username": "ghost", "password": "whatever123"})
    assert resp.status_code == 401


def test_me_with_token(client):
    client.post("/api/auth/register", json=REGISTER)
    token = client.post("/api/auth/login", json={"username": "alice", "password": "supersecret123"}).json()["access_token"]
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["username"] == "alice"


def test_protected_endpoint_without_token(client):
    assert client.get("/api/targets").status_code == 401


def test_invalid_token_rejected(client):
    resp = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401
