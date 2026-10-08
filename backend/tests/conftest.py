import os
import sys
from pathlib import Path

# Set BEFORE the app is imported. load_dotenv() never overrides variables that already exist, so these win
# over backend/.env: tests must not send real emails, call the real AI, or run the real scanner.
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-for-hs256")
os.environ["USE_MOCK_SCANNER"] = "true"
os.environ["SMTP_HOST"] = ""
os.environ["BREVO_API_KEY"] = ""
os.environ["ANTHROPIC_API_KEY"] = "test-key-not-used"
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root, so `import scanner` works

import httpx
import pytest
from mongomock_motor import AsyncMongoMockClient

import app.database as database

# Swap the real MongoDB for an in-memory one BEFORE other modules import `db`.
database.client = AsyncMongoMockClient(tz_aware=True)
database.db = database.client["securesphere_test"]

from app.main import app  # noqa: E402  (must come after the database swap)
from app.services import scan_jobs  # noqa: E402

PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
async def clean_db():
    for name in await database.db.list_collection_names():
        await database.db[name].delete_many({})
    await database.create_indexes()
    scan_jobs.JOBS.clear()
    yield


@pytest.fixture(autouse=True)
def no_real_dns(monkeypatch):
    """Domain checks would do real DNS lookups; pretend every test domain is a public site."""
    monkeypatch.setattr("app.utils.validators.assert_public", lambda domain: PUBLIC_IP)
    # Sign-up checks the email domain's mail server in DNS; tests pretend every domain can receive mail.
    monkeypatch.setattr("app.routers.auth.email_domain_accepts_mail", lambda email: True)


@pytest.fixture
async def client():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def signup(client, email="user@example.com", password="password123", name="Test User", verified=True) -> dict:
    """Creates an account and returns auth headers for it. By default the email is marked confirmed,
    as if the user clicked the link, because scanning and monitoring need a confirmed email."""
    res = await client.post("/auth/signup", json={"name": name, "email": email, "password": password})
    assert res.status_code == 201, res.text
    if verified:
        await database.db.users.update_one({"email": email.lower()}, {"$set": {"email_verified": True}})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}
