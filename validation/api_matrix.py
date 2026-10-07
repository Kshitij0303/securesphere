"""Black-box API test matrix: calls a RUNNING SecureSphere backend over HTTP (no mocks).

    python validation/api_matrix.py http://localhost:8000 --local      # full matrix (creates test users)
    python validation/api_matrix.py https://securesphere-api-sjja.onrender.com   # read-only checks

--local creates throw-away users, marks them confirmed directly in the local MongoDB and runs one real
scan (github.com). Start that backend with SMTP_HOST empty so no real emails are sent. Without --local only
checks that create nothing are run (safe against the deployed server)."""
import json
import os
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8000"
LOCAL = "--local" in sys.argv
GOOD_ORIGIN = "http://localhost:5173" if LOCAL else "https://securesphere-psi.vercel.app"
results: list[dict] = []
client = httpx.Client(base_url=BASE, timeout=90)


def check(category: str, name: str, method: str, path: str, expect, *, headers=None, json_body=None,
          content=None, verify=None):
    """One request. expect = allowed status code(s); verify(response) may return a problem string."""
    started = time.perf_counter()
    try:
        r = client.request(method, path, headers=headers, json=json_body, content=content)
    except httpx.HTTPError as e:
        results.append({"category": category, "test": name, "result": "FAIL", "detail": f"request failed: {e!r}"})
        return None
    ms = round((time.perf_counter() - started) * 1000)
    allowed = expect if isinstance(expect, tuple) else (expect,)
    problem = None if r.status_code in allowed else f"got {r.status_code}, expected {allowed}: {r.text[:120]}"
    body = r.text.lower()
    if not problem and ("traceback" in body or 'file "' in body):
        problem = "stack trace exposed to the client"
    if not problem and verify:
        problem = verify(r)
    results.append({"category": category, "test": name, "result": "FAIL" if problem else "PASS",
                    "status": r.status_code, "ms": ms, "detail": problem or ""})
    return r


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def detail_has(text: str):
    return lambda r: None if text.lower() in json.dumps(r.json()).lower() else f"message lacks '{text}': {r.text[:120]}"


def forged_token(secret: str, sub: str, minutes: int) -> str:
    import jwt
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": sub, "iat": int(now.timestamp()), "exp": now + timedelta(minutes=minutes)}, secret, "HS256")


# ---------------------------------------------------------------- safe checks (any server)
check("system", "health (server and database up)", "GET", "/health", 200,
      verify=lambda r: None if r.json().get("status") == "ok" and r.json().get("database", "ok") == "ok" else r.text)
check("security", "API sends security headers", "GET", "/health", 200, verify=lambda r: None if all(
    h in r.headers for h in ("strict-transport-security", "content-security-policy", "x-frame-options",
                             "x-content-type-options", "referrer-policy")) else f"missing headers: {dict(r.headers)}")
check("security", "unknown path returns JSON 404", "GET", "/does-not-exist", 404)
check("security", "PUT /health not allowed", "PUT", "/health", 405)
check("security", "DELETE /users/me not allowed", "DELETE", "/users/me", (401, 405))
check("cors", "preflight from the website is allowed", "OPTIONS", "/auth/login", 200,
      headers={"Origin": GOOD_ORIGIN, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"},
      verify=lambda r: None if r.headers.get("access-control-allow-origin") == GOOD_ORIGIN else f"ACAO={r.headers.get('access-control-allow-origin')}")
check("cors", "preflight from an unknown site is refused", "OPTIONS", "/auth/login", (400, 200),
      headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
      verify=lambda r: None if not r.headers.get("access-control-allow-origin") else f"ACAO={r.headers.get('access-control-allow-origin')}")
check("cors", "no wildcard origin with credentials", "GET", "/health", 200, headers={"Origin": "https://evil.example"},
      verify=lambda r: None if r.headers.get("access-control-allow-origin") in (None,) else f"ACAO={r.headers.get('access-control-allow-origin')}")
for path in ("/users/me", "/history", "/monitor", "/alerts", "/alerts/unread-count"):
    check("auth", f"GET {path} without token -> 401", "GET", path, 401)
check("auth", "garbage token -> 401", "GET", "/users/me", 401, headers=auth("not.a.jwt"))
check("auth", "token signed with wrong secret -> 401", "GET", "/users/me", 401,
      headers=auth(forged_token("wrong-secret-wrong-secret-wrong-secret", "6ac53781bf3521a6aa8ea122", 30)))
check("auth", "POST /scan/jobs without token -> 401", "POST", "/scan/jobs", 401, json_body={"domain": "github.com"})
check("auth", "login: wrong password / unknown user", "POST", "/auth/login", 401,
      json_body={"email": f"nobody-{secrets.token_hex(4)}@gmail.com", "password": "wrongpass123"},
      verify=detail_has("incorrect email or password"))
check("validation", "login: empty body -> 422", "POST", "/auth/login", 422, json_body={})
check("validation", "login: malformed email -> 422", "POST", "/auth/login", 422, json_body={"email": "abc", "password": "x"})
check("validation", "login: malformed JSON -> 422", "POST", "/auth/login", 422, content=b'{"email": ', headers={"Content-Type": "application/json"})
check("validation", "signup: invalid email -> 422", "POST", "/auth/signup", 422, json_body={"name": "A", "email": "not-an-email", "password": "password123"})
check("validation", "signup: short password -> 422", "POST", "/auth/signup", 422, json_body={"name": "A", "email": "a@gmail.com", "password": "short"})
check("validation", "signup: empty fields -> 422", "POST", "/auth/signup", 422, json_body={"name": "", "email": "", "password": ""})
check("validation", "signup: wrong types -> 422", "POST", "/auth/signup", 422, json_body={"name": 5, "email": 123, "password": None})
check("validation", "signup: 51-character name -> 422", "POST", "/auth/signup", 422, json_body={"name": "x" * 51, "email": "a@gmail.com", "password": "password123"})
check("validation", "signup: 100-character password -> 422", "POST", "/auth/signup", 422, json_body={"name": "A", "email": "a@gmail.com", "password": "p" * 100})
check("auth", "forgot-password: same reply for unknown email", "POST", "/auth/forgot-password", 200,
      json_body={"email": f"nobody-{secrets.token_hex(4)}@gmail.com"}, verify=detail_has("if an account exists"))
check("auth", "reset-password: invalid token -> 400", "POST", "/auth/reset-password", 400, json_body={"token": "x" * 30, "new_password": "newpassword1"})
check("auth", "verify-email: invalid token -> 400", "POST", "/auth/verify-email", 400, json_body={"token": "x" * 30})
check("validation", "verify-email: token too short -> 422", "POST", "/auth/verify-email", 422, json_body={"token": "x"})

# ---------------------------------------------------------------- full matrix (local only)
if LOCAL:
    from pymongo import MongoClient
    from dotenv import dotenv_values
    env = dotenv_values(os.path.join(os.path.dirname(__file__), "..", "backend", ".env"))
    mongo = MongoClient(env.get("MONGO_URL") or "mongodb://localhost:27017")[env.get("DB_NAME") or "securesphere"]
    tag = secrets.token_hex(3)
    email_a, email_b = f"ss-test-a-{tag}@gmail.com", f"ss-test-b-{tag}@gmail.com"

    r = check("auth", "signup: valid", "POST", "/auth/signup", 201, json_body={"name": "Tester A", "email": email_a, "password": "password123"})
    token_a = r.json()["access_token"]
    check("auth", "signup: duplicate email -> 409", "POST", "/auth/signup", 409, json_body={"name": "A", "email": email_a.upper(), "password": "password123"})
    check("auth", "signup: email domain with no mail server -> 400", "POST", "/auth/signup", 400,
          json_body={"name": "A", "email": f"x-{tag}@f.com", "password": "password123"}, verify=detail_has("can't send email"))
    token_b = check("auth", "signup: second user", "POST", "/auth/signup", 201, json_body={"name": "Tester B", "email": email_b, "password": "password123"}).json()["access_token"]
    check("auth", "unconfirmed user cannot scan -> 403", "POST", "/scan/jobs", 403, headers=auth(token_a), json_body={"domain": "github.com"}, verify=detail_has("confirm your email"))
    check("auth", "unconfirmed user can read profile", "GET", "/users/me", 200, headers=auth(token_a),
          verify=lambda r: None if r.json()["email_verified"] is False and "password_hash" not in r.text else r.text[:150])
    mongo.users.update_many({"email": {"$in": [email_a, email_b]}}, {"$set": {"email_verified": True}})
    check("auth", "login: valid", "POST", "/auth/login", 200, json_body={"email": email_a, "password": "password123"})
    check("auth", "expired token -> 401", "GET", "/users/me", 401, headers=auth(forged_token(env["JWT_SECRET"], str(mongo.users.find_one({"email": email_a})["_id"]), -5)))
    check("auth", "token of a deleted user -> 401", "GET", "/users/me", 401, headers=auth(forged_token(env["JWT_SECRET"], "0123456789abcdef01234567", 30)))

    # domain validation and normalisation
    for raw, code, note in [("", 422, "empty"), (None, 422, "null"), ("go", 422, "too short"), ("x" * 300, 422, "too long"),
                            ("google com", 400, "space"), ("localhost", 400, "no TLD"), ("127.0.0.1", 400, "IP address"),
                            ("javascript:alert(1)", 400, "script")]:
        check("validation", f"scan domain {note!s}: {str(raw)[:30]!r}", "POST", "/scan/jobs", code, headers=auth(token_a), json_body={"domain": raw})

    def wait(job_id: str, token: str) -> dict:
        for _ in range(90):
            job = client.get(f"/scan/jobs/{job_id}", headers=auth(token)).json()
            if job["status"] != "running":
                return job
            time.sleep(1)
        return {"status": "timeout"}

    # SSRF: a public name that points to a private address must be refused
    ssrf = client.post("/scan/jobs", headers=auth(token_b), json={"domain": "10.0.0.1.nip.io"}).json()
    job = wait(ssrf["job_id"], token_b) if "job_id" in ssrf else {"error": ssrf.get("detail", "")}
    results.append({"category": "security", "test": "SSRF: domain resolving to 10.0.0.1 is refused",
                    "result": "PASS" if "private network" in (job.get("error") or "") else "FAIL", "detail": str(job.get("error"))[:120]})
    bad = client.post("/scan/jobs", headers=auth(token_b), json={"domain": f"no-such-site-{tag}.invalid"}).json()
    job = wait(bad["job_id"], token_b) if "job_id" in bad else {"error": bad.get("detail", "")}
    results.append({"category": "error handling", "test": "nonexistent domain -> clear message",
                    "result": "PASS" if "doesn't exist" in (job.get("error") or "") else "FAIL", "detail": str(job.get("error"))[:120]})

    # one real scan, then history / report / compare / ownership
    started = time.perf_counter()
    start = client.post("/scan/jobs", headers=auth(token_a), json={"domain": "example.org"}).json()
    job = wait(start["job_id"], token_a)
    secs = round(time.perf_counter() - started, 1)
    ok = job.get("status") == "done" and 0 <= job["scan"]["score"] <= 100 and len(job["steps"]) >= 7
    results.append({"category": "scanner", "test": f"real (uncached) scan example.org via API ({secs}s, steps={len(job.get('steps', []))})",
                    "result": "PASS" if ok else "FAIL", "detail": "" if ok else str(job)[:150], "ms": int(secs * 1000)})
    scan_id = job["scan"]["id"]
    for raw in ("https://GitHub.com/some/path?q=1", "github.com:443"):
        r = check("validation", f"scan domain normalised: {raw}", "POST", "/scan/jobs", 202, headers=auth(token_a), json_body={"domain": raw},
                  verify=lambda r: None if r.json()["domain"] == "github.com" else r.text)
        if r is not None and r.status_code == 202:
            wait(r.json()["job_id"], token_a)  # max 2 scans at a time per user
    check("validation", "scan domain with another port -> 400 with reason", "POST", "/scan/jobs", 400, headers=auth(token_a),
          json_body={"domain": "github.com:8443"}, verify=detail_has("standard https port"))

    check("database", "history lists the scan", "GET", "/history", 200, headers=auth(token_a),
          verify=lambda r: None if any(h["id"] == scan_id for h in r.json()) else "scan missing from history")
    check("database", "saved report can be reopened", "GET", f"/scan/{scan_id}", 200, headers=auth(token_a))
    check("authorization", "IDOR: other user cannot read the report", "GET", f"/scan/{scan_id}", 404, headers=auth(token_b))
    check("authorization", "IDOR: other user cannot compare it", "GET", f"/scan/{scan_id}/compare", 404, headers=auth(token_b))
    check("authorization", "IDOR: other user's job id -> 404", "GET", f"/scan/jobs/{start['job_id']}", 404, headers=auth(token_b))
    check("authorization", "other user's history is empty", "GET", "/history", 200, headers=auth(token_b),
          verify=lambda r: None if all(h["id"] != scan_id for h in r.json()) else "leaked scan")
    check("validation", "invalid scan id -> 404", "GET", "/scan/not-an-id", 404, headers=auth(token_a))
    started = time.perf_counter()
    again = wait(client.post("/scan/jobs", headers=auth(token_a), json={"domain": "example.org"}).json()["job_id"], token_a)
    results.append({"category": "performance", "test": f"repeat scan within 5 min reuses result ({round(time.perf_counter() - started, 1)}s)",
                    "result": "PASS" if again.get("steps") == ["cached"] and again["scan"]["score"] == job["scan"]["score"] else "FAIL",
                    "detail": str(again.get("steps"))})

    # monitoring + alerts ownership
    mon = check("api", "monitor: add", "POST", "/monitor", 201, headers=auth(token_a), json_body={"domain": "github.com"})
    check("api", "monitor: duplicate -> 409", "POST", "/monitor", 409, headers=auth(token_a), json_body={"domain": "github.com"})
    if mon is not None and mon.status_code == 201:
        check("authorization", "IDOR: other user cannot delete my monitor", "DELETE", f"/monitor/{mon.json()['id']}", 404, headers=auth(token_b))
        check("api", "monitor: delete own", "DELETE", f"/monitor/{mon.json()['id']}", 204, headers=auth(token_a))
    check("validation", "monitor: delete invalid id -> 404", "DELETE", "/monitor/xyz", 404, headers=auth(token_a))
    uid_a = str(mongo.users.find_one({"email": email_a})["_id"])
    alert_id = str(mongo.alerts.insert_one({"user_id": uid_a, "domain": "github.com", "message": "test", "read": False,
                                            "created_at": datetime.now(timezone.utc)}).inserted_id)
    check("api", "alerts: unread count", "GET", "/alerts/unread-count", 200, headers=auth(token_a), verify=lambda r: None if r.json()["count"] == 1 else r.text)
    check("authorization", "IDOR: other user cannot mark my alert", "PATCH", f"/alerts/{alert_id}/read", 404, headers=auth(token_b))
    check("api", "alerts: mark own as read", "PATCH", f"/alerts/{alert_id}/read", 200, headers=auth(token_a))

    # profile
    check("validation", "profile: empty name -> 422", "PATCH", "/users/me", 422, headers=auth(token_a), json_body={"name": ""})
    check("api", "profile: rename", "PATCH", "/users/me", 200, headers=auth(token_a), json_body={"name": "Renamed"})
    check("auth", "change password: wrong current -> 400", "POST", "/users/me/password", 400, headers=auth(token_a),
          json_body={"current_password": "wrongpass1", "new_password": "newpassword1"})
    check("api", "assistant without AI key -> 503 (website falls back)", "POST", "/assistant", (503, 502), headers=auth(token_a),
          json_body={"message": "What should I fix?", "scan_id": scan_id})
    check("validation", "assistant: empty message -> 422", "POST", "/assistant", 422, headers=auth(token_a), json_body={"message": ""})

    # brute force lockout (on user B)
    for i in range(5):
        client.post("/auth/login", json={"email": email_b, "password": "wrongpass123"})
    check("auth", "login locked after 5 failures -> 429", "POST", "/auth/login", 429, json_body={"email": email_b, "password": "password123"})

    # clean up the throw-away users and their data
    for email in (email_a, email_b):
        u = mongo.users.find_one({"email": email})
        if u:
            for coll in ("scans", "monitors", "alerts", "email_verifications", "assistant_usage"):
                mongo[coll].delete_many({"user_id": str(u["_id"])})
            mongo.users.delete_one({"_id": u["_id"]})
    mongo.login_failures.delete_many({"email": {"$in": [email_a, email_b]}})

# ---------------------------------------------------------------- report
width = max(len(r["test"]) for r in results)
for r in results:
    print(f"{r['result']:5} {r['category']:15} {r['test']:{width}} {r.get('status', ''):>4} {str(r.get('ms', '')):>6}ms {r['detail']}")
passed = sum(r["result"] == "PASS" for r in results)
print(f"\n{passed}/{len(results)} passed against {BASE}")
json.dump(results, open(os.path.join(os.path.dirname(__file__), f"api_matrix_{'local' if LOCAL else 'remote'}.json"), "w"), indent=1)
