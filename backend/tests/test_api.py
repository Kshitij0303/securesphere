"""API tests: every endpoint the website uses, with an in-memory database and the mock scanner."""
import asyncio
from datetime import datetime, timezone

import anthropic
import httpx
import pytest

import app.routers.assistant as assistant_module
from app.database import db
from app.services.tokens import hash_token
from tests.conftest import signup

KNOWN_TOKEN = "known-token-" + "x" * 20


def use_known_token(monkeypatch, module: str) -> None:
    """Emailed links contain a random token; tests swap in a known one so they can "click" the link."""
    monkeypatch.setattr(f"{module}.new_token", lambda: (KNOWN_TOKEN, hash_token(KNOWN_TOKEN)))


# ---------- sign-up, login, brute-force protection ----------

async def test_signup_and_login(client):
    await signup(client)
    res = await client.post("/auth/login", json={"email": "USER@example.com", "password": "password123"})
    assert res.status_code == 200 and res.json()["access_token"]


async def test_duplicate_signup_rejected(client):
    await signup(client)
    res = await client.post("/auth/signup", json={"name": "X", "email": "user@example.com", "password": "password123"})
    assert res.status_code == 409


async def test_wrong_password_and_unknown_email_get_same_message(client):
    await signup(client)
    wrong = await client.post("/auth/login", json={"email": "user@example.com", "password": "wrongpass1"})
    unknown = await client.post("/auth/login", json={"email": "nobody@example.com", "password": "wrongpass1"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


async def test_login_locks_after_five_failures(client):
    await signup(client)
    for _ in range(5):
        res = await client.post("/auth/login", json={"email": "user@example.com", "password": "wrongpass1"})
        assert res.status_code == 401
    # Even the right password is refused while locked.
    res = await client.post("/auth/login", json={"email": "user@example.com", "password": "password123"})
    assert res.status_code == 429


async def test_successful_login_clears_failures(client):
    await signup(client)
    for _ in range(4):
        await client.post("/auth/login", json={"email": "user@example.com", "password": "wrongpass1"})
    assert (await client.post("/auth/login", json={"email": "user@example.com", "password": "password123"})).status_code == 200
    assert await db.login_failures.count_documents({"email": "user@example.com"}) == 0


async def test_protected_routes_need_a_token(client):
    for path in ("/users/me", "/history", "/monitor", "/alerts"):
        assert (await client.get(path)).status_code == 401


# ---------- password change, reset, sessions ----------

async def test_password_change_logs_out_other_sessions(client):
    headers = await signup(client)
    await asyncio.sleep(1.1)  # tokens carry whole seconds
    res = await client.post("/users/me/password", headers=headers,
                            json={"current_password": "password123", "new_password": "newpassword1"})
    assert res.status_code == 200
    new_headers = {"Authorization": f"Bearer {res.json()['access_token']}"}
    assert (await client.get("/users/me", headers=headers)).status_code == 401      # old session ended
    assert (await client.get("/users/me", headers=new_headers)).status_code == 200  # this one continues


async def test_password_change_needs_current_password(client):
    headers = await signup(client)
    res = await client.post("/users/me/password", headers=headers,
                            json={"current_password": "wrongpass1", "new_password": "newpassword1"})
    assert res.status_code == 400


async def test_forgot_password_does_not_reveal_accounts(client):
    await signup(client)
    a = await client.post("/auth/forgot-password", json={"email": "user@example.com"})
    b = await client.post("/auth/forgot-password", json={"email": "nobody@example.com"})
    assert a.json() == b.json()


async def test_reset_password_flow(client, monkeypatch):
    headers = await signup(client)
    use_known_token(monkeypatch, "app.routers.password_reset")
    await client.post("/auth/forgot-password", json={"email": "user@example.com"})
    await asyncio.sleep(1.1)
    res = await client.post("/auth/reset-password", json={"token": KNOWN_TOKEN, "new_password": "brandnew123"})
    assert res.status_code == 200
    # The link works only once, the old password and old sessions stop working, the new password works.
    again = await client.post("/auth/reset-password", json={"token": KNOWN_TOKEN, "new_password": "other12345"})
    assert again.status_code == 400
    assert (await client.post("/auth/login", json={"email": "user@example.com", "password": "password123"})).status_code == 401
    assert (await client.post("/auth/login", json={"email": "user@example.com", "password": "brandnew123"})).status_code == 200
    assert (await client.get("/users/me", headers=headers)).status_code == 401


# ---------- email verification ----------

async def test_email_verification_flow(client, monkeypatch):
    use_known_token(monkeypatch, "app.services.verification")
    headers = await signup(client)
    assert (await client.get("/users/me", headers=headers)).json()["email_verified"] is False
    assert (await client.post("/auth/verify-email", json={"token": KNOWN_TOKEN})).status_code == 200
    assert (await client.get("/users/me", headers=headers)).json()["email_verified"] is True
    assert (await client.post("/auth/verify-email", json={"token": KNOWN_TOKEN})).status_code == 400  # used once


async def test_resend_verification_is_limited(client):
    headers = await signup(client)  # sign-up already sent one
    for _ in range(2):
        assert (await client.post("/users/me/resend-verification", headers=headers)).status_code == 200
    assert (await client.post("/users/me/resend-verification", headers=headers)).status_code == 429


# ---------- profile ----------

async def test_profile_never_contains_the_password(client):
    headers = await signup(client)
    body = (await client.get("/users/me", headers=headers)).json()
    assert body["name"] == "Test User" and "password_hash" not in body
    res = await client.patch("/users/me", headers=headers, json={"name": "New Name"})
    assert res.json()["name"] == "New Name"


# ---------- scans ----------

async def run_job(client, headers, domain="example.com") -> dict:
    res = await client.post("/scan/jobs", headers=headers, json={"domain": domain})
    assert res.status_code == 202, res.text
    job_id = res.json()["job_id"]
    for _ in range(50):
        job = (await client.get(f"/scan/jobs/{job_id}", headers=headers)).json()
        if job["status"] != "running":
            return job
        await asyncio.sleep(0.05)
    pytest.fail("scan job did not finish")


async def test_scan_job_and_history(client):
    headers = await signup(client)
    job = await run_job(client, headers)
    assert job["status"] == "done" and job["scan"]["domain"] == "example.com"
    history = (await client.get("/history", headers=headers)).json()
    assert [h["domain"] for h in history] == ["example.com"]
    scan = (await client.get(f"/scan/{job['scan']['id']}", headers=headers)).json()
    assert scan["score"] == job["scan"]["score"]


async def test_bad_domain_is_rejected_before_scanning(client):
    headers = await signup(client)
    res = await client.post("/scan/jobs", headers=headers, json={"domain": "not a domain"})
    assert res.status_code == 400


async def test_scans_are_private(client):
    owner = await signup(client)
    other = await signup(client, email="other@example.com")
    job = await run_job(client, owner)
    assert (await client.get(f"/scan/{job['scan']['id']}", headers=other)).status_code == 404
    assert (await client.get("/scan/jobs/nonexistent", headers=other)).status_code == 404


async def test_recent_result_is_reused(client):
    first = await signup(client)
    second = await signup(client, email="second@example.com")
    await run_job(client, first)
    job = await run_job(client, second)
    assert job["steps"] == ["cached"] and job["scan"]["cached"] is True
    assert job["scan"]["user_id"] != (await db.scans.find_one({"cached": {"$ne": True}}))["user_id"]


async def test_compare_with_previous_scan(client, monkeypatch):
    headers = await signup(client)
    monkeypatch.setattr("app.services.scan_service.SCAN_CACHE_SECONDS", 0)  # force two real scans
    first = await run_job(client, headers)
    nothing = (await client.get(f"/scan/{first['scan']['id']}/compare", headers=headers)).json()
    assert nothing == {"previous": None}
    second = await run_job(client, headers)
    diff = (await client.get(f"/scan/{second['scan']['id']}/compare", headers=headers)).json()
    assert diff["previous"]["id"] == first["scan"]["id"]
    assert diff["score_change"] == 0 and diff["new_findings"] == [] and diff["fixed_findings"] == []


# ---------- monitoring and alerts ----------

async def test_monitoring_scans_right_away(client):
    headers = await signup(client)
    res = await client.post("/monitor", headers=headers, json={"domain": "example.com"})
    assert res.status_code == 201
    monitors = (await client.get("/monitor", headers=headers)).json()
    assert monitors[0]["last_score"] is not None  # the first scan already ran
    assert (await client.post("/monitor", headers=headers, json={"domain": "example.com"})).status_code == 409


async def test_unread_alert_count_and_mark_read(client):
    headers = await signup(client)
    me = (await client.get("/users/me", headers=headers)).json()
    await db.alerts.insert_one({"user_id": me["id"], "domain": "example.com", "message": "x", "read": False,
                                "created_at": datetime.now(timezone.utc)})
    assert (await client.get("/alerts/unread-count", headers=headers)).json() == {"count": 1}
    alert_id = (await client.get("/alerts", headers=headers)).json()[0]["id"]
    assert (await client.patch(f"/alerts/{alert_id}/read", headers=headers)).status_code == 200
    assert (await client.get("/alerts/unread-count", headers=headers)).json() == {"count": 0}


# ---------- AI assistant ----------

class FakeBlock:
    type = "text"
    text = "HSTS tells browsers to always use HTTPS."


class FakeResponse:
    stop_reason = "end_turn"
    content = [FakeBlock()]


def fake_client(messages, api_key="test-key"):
    """Stands in for anthropic.AsyncAnthropic so tests never call the real API."""
    return type("FakeClient", (), {"api_key": api_key, "auth_token": None,
                                   "beta": type("Beta", (), {"messages": messages})()})()


class FakeMessages:
    def __init__(self):
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return FakeResponse()


async def test_assistant_answers_from_the_users_own_scan(client, monkeypatch):
    fake = FakeMessages()
    monkeypatch.setattr(assistant_module, "client", fake_client(fake))
    headers = await signup(client)
    job = await run_job(client, headers)
    res = await client.post("/assistant", headers=headers, json={"message": "What is HSTS?", "scan_id": job["scan"]["id"]})
    assert res.status_code == 200 and "HSTS" in res.json()["reply"]
    sent_system = fake.calls[0]["system"][1]["text"]
    assert "example.com" in sent_system and "<scan_data>" in sent_system  # the saved scan, loaded by id


async def test_assistant_cannot_read_other_users_scans(client, monkeypatch):
    fake = FakeMessages()
    monkeypatch.setattr(assistant_module, "client", fake_client(fake))
    owner = await signup(client)
    other = await signup(client, email="other@example.com")
    job = await run_job(client, owner)
    await client.post("/assistant", headers=other, json={"message": "Explain", "scan_id": job["scan"]["id"]})
    assert "not found" in fake.calls[0]["system"][1]["text"]


async def test_assistant_not_configured_returns_503(client, monkeypatch):
    fake = FakeMessages()
    monkeypatch.setattr(assistant_module, "client", fake_client(fake, api_key=None))
    headers = await signup(client)
    res = await client.post("/assistant", headers=headers, json={"message": "hi"})
    assert res.status_code == 503 and fake.calls == []  # no request is even attempted


async def test_assistant_api_errors_become_friendly_messages(client, monkeypatch):
    class Failing:
        async def create(self, **kwargs):
            raise anthropic.APIConnectionError(request=httpx.Request("POST", "https://api.anthropic.com"))

    monkeypatch.setattr(assistant_module, "client", fake_client(Failing()))
    headers = await signup(client)
    res = await client.post("/assistant", headers=headers, json={"message": "hi"})
    assert res.status_code == 502 and "could not be reached" in res.json()["detail"]


# ---------- SecureSphere's own security headers ----------

async def test_api_sends_security_headers(client):
    res = await client.get("/health")
    for header in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                   "X-Content-Type-Options", "Referrer-Policy"):
        assert header in res.headers
    assert res.headers["Content-Security-Policy"].startswith("default-src 'none'")
