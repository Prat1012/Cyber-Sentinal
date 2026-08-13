"""Pytest fixtures.

Environment variables are configured BEFORE the application is imported so the
engine, settings and tables target an isolated test database.
"""

import os
from pathlib import Path

import pytest

# --- Test environment (must be set before importing app modules) ---
# In-memory SQLite + StaticPool keeps the suite fast and avoids file locks.
TEST_DB = None

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["APP_ENV"] = "test"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["AUTH_ENABLED"] = "true"
# Low bcrypt cost for fast test runs (production default is 12).
os.environ["BCRYPT_ROUNDS"] = "4"
# Raise rate limits so tests never trip them.
os.environ["RATE_LIMIT_REQUESTS"] = "100000"
os.environ["AUTH_RATE_LIMIT_REQUESTS"] = "100000"
os.environ["ALLOW_EXTERNAL_TARGETS"] = "false"
# Force the fast built-in scanner in the test suite (deterministic, no real
# nmap binary required). The live nmap path is covered by scripts/e2e_live.py
# and the nmap XML parser tests. This also overrides any NMAP_BIN_PATH that
# may be present in a local backend/.env.
os.environ["NMAP_BIN_PATH"] = "nmap-not-installed-in-tests"
os.environ["WEB_CONNECT_TIMEOUT"] = "3"
os.environ["WEB_READ_TIMEOUT"] = "5"
os.environ["DIRECTORY_DELAY_SECONDS"] = "0"

from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal  # noqa: E402
from app.main import app  # noqa: E402

TEST_USER = {"username": "tester", "password": "supersecret123", "email": "tester@example.com"}


@pytest.fixture(scope="session", autouse=True)
def _session_db():
    yield
    # Release pooled connections (in-memory DB disappears with the process).
    from app.database import engine

    engine.dispose()


@pytest.fixture(autouse=True)
def clean_tables():
    """Reset all tables before each test."""
    with SessionLocal() as db:
        for table in reversed(Base.metadata.sorted_tables):
            db.execute(table.delete())
        db.commit()
    yield
    with SessionLocal() as db:
        for table in reversed(Base.metadata.sorted_tables):
            db.execute(table.delete())
        db.commit()


@pytest.fixture()
def client():
    # No context manager: lifespan (job worker thread) is intentionally NOT
    # started so API tests never run background scans.
    return TestClient(app)


@pytest.fixture()
def register_user(client):
    resp = client.post("/api/auth/register", json=TEST_USER)
    assert resp.status_code == 201, resp.text
    return dict(TEST_USER)


@pytest.fixture()
def auth_headers(client, register_user):
    resp = client.post("/api/auth/login", json={"username": register_user["username"], "password": register_user["password"]})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def created_target(client, auth_headers):
    resp = client.post(
        "/api/targets",
        headers=auth_headers,
        json={"name": "Local lab", "address": "127.0.0.1", "description": "pytest lab"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.fixture()
def lab_server():
    """Start the local HTTP lab on 127.0.0.1:18080."""
    from tests.lab_server import LabHTTPServer

    with LabHTTPServer() as server:
        yield server


@pytest.fixture()
def tls_server():
    """Start the self-signed TLS lab on 127.0.0.1:18443."""
    from tests.lab_server import LabTLSServer

    with LabTLSServer() as server:
        yield server
