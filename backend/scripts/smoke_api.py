"""Quick API smoke test used during development (not part of pytest suite)."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("DATABASE_URL", "sqlite:///./smoke_test.db")
os.environ.setdefault("SECRET_KEY", "smoke-test-secret-key-not-for-production")
os.environ.setdefault("AUTO_CREATE_TABLES", "true")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)

print("1. health:", client.get("/api/health").status_code, client.get("/api/health").json())

r = client.post("/api/auth/register", json={"username": "demo", "password": "supersecret123", "email": "demo@example.com"})
print("2. register:", r.status_code, r.json().get("username"))

r = client.post("/api/auth/login", json={"username": "demo", "password": "supersecret123"})
print("3. login:", r.status_code, "access_token" in r.json())
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

r = client.get("/api/auth/me", headers=headers)
print("4. me:", r.status_code, r.json().get("username"))

r = client.post("/api/targets", headers=headers, json={"name": "Local lab", "address": "127.0.0.1", "description": "lab"})
print("5. create target:", r.status_code, r.json().get("address"))
target_id = r.json()["id"]

r = client.post("/api/targets", headers=headers, json={"name": "bad", "address": "127.0.0.1; rm -rf /"})
print("6. reject malicious target:", r.status_code, r.json()["error"]["code"])

r = client.get("/api/targets", headers=headers)
print("7. list targets:", r.status_code, len(r.json()))

r = client.get("/api/dashboard/summary", headers=headers)
print("8. dashboard:", r.status_code, r.json()["total_targets"])

print("\nSMOKE TEST PASSED")
