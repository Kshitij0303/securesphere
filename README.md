# SecureSphere

Checks a website's HTTPS setup (certificate, TLS versions, ciphers, security headers, cookies, redirects,
DNS and known TLS vulnerabilities), explains every problem in plain English with a fix, and keeps watching
monitored sites with email alerts.

| Folder | What it is |
|---|---|
| `scanner/` | Part 1: the scanner, scoring rules and explanations (Python). `python scan.py github.com` |
| `backend/` | Part 2: FastAPI + MongoDB API (accounts, scans, monitoring, alerts, AI assistant) |
| `Frontend/Frontend/` | Part 3: React website (Vite + Tailwind) |

## Run it on your computer

Needs Python 3.12+, Node 20+ and MongoDB. Use three terminals:

```powershell
# 1. MongoDB
& "C:\Program Files\MongoDB\Server\8.2\bin\mongod.exe" --dbpath "$HOME\mongo-data"

# 2. Backend (first time: copy backend\.env.example to backend\.env and fill it in)
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload            # http://localhost:8000/docs

# 3. Website
cd Frontend\Frontend
npm install
npm run dev                              # http://localhost:5173
```

Without SMTP settings, email links (password reset, email confirmation) are printed in the backend terminal.
Without `ANTHROPIC_API_KEY`, the assistant uses simple built-in answers instead of AI.

## Or run everything with Docker

```bash
docker compose up --build                # website http://localhost:8080, API http://localhost:8000
```

## Tests

```powershell
cd backend
pip install -r requirements-dev.txt
pytest                                    # scanner rules + every API endpoint (no internet needed)
$env:RUN_NETWORK_TESTS="1"; pytest tests/test_scanner_accuracy.py -v   # accuracy against badssl.com (~4 min)
```

The accuracy tests scan sites whose problems are known in advance (expired certificate, wrong host,
self-signed, untrusted root, TLS 1.0/1.1, RC4, no HTTPS redirect) and check the scanner reports exactly that.

## Put it online

1. **Database:** create a free cluster on [MongoDB Atlas](https://www.mongodb.com/atlas). Copy its connection
   string (`mongodb+srv://...`). Under *Network Access*, allow connections from anywhere (`0.0.0.0/0`), since
   Render's address changes.
2. **Backend:** push this repository to GitHub. On [Render](https://render.com) choose *New -> Blueprint* and pick
   the repository; `render.yaml` sets everything up. Fill in `MONGO_URL`, your SMTP settings and (optionally)
   `ANTHROPIC_API_KEY`. Leave `CORS_ORIGINS` and `FRONTEND_URL` for step 4.
3. **Website:** on [Vercel](https://vercel.com) import the same repository, set *Root Directory* to
   `Frontend/Frontend`, and add the environment variable `VITE_API_URL` = your Render address
   (e.g. `https://securesphere-api.onrender.com`). If your Render address is different, also change it in the
   `connect-src` part of `Frontend/Frontend/vercel.json`.
4. Back on Render, set `CORS_ORIGINS` and `FRONTEND_URL` to your Vercel address and redeploy.
5. Scan your own Vercel address with SecureSphere: it should get a top score.

Note: Render's free plan sleeps when idle, so the nightly monitoring scan only runs on a paid plan
(or move the daily job to a scheduled task).

## Settings (`backend/.env`)

| Setting | Meaning |
|---|---|
| `MONGO_URL`, `DB_NAME` | Database connection |
| `JWT_SECRET` | Long random secret that signs logins. Changing it logs everyone out |
| `CORS_ORIGINS`, `FRONTEND_URL` | Address of the website (allowed caller, and used in emailed links) |
| `USE_MOCK_SCANNER` | `true` = fake scan data for development |
| `SMTP_*` | Email server (e.g. Gmail with an App Password) |
| `ANTHROPIC_API_KEY`, `ASSISTANT_MODEL` | AI assistant (optional) |
| `MAX_FAILED_LOGINS`, `LOGIN_LOCK_MINUTES` | Brute-force protection |
| `SCAN_CACHE_SECONDS` | Reuse a scan of the same site from the last N seconds (0 = off) |

All settings and their defaults are listed in `backend/.env.example`.

## Security notes

- Passwords are hashed with bcrypt; reset and confirmation links are single-use, expire, and only their hash is stored.
- Logins lock after 5 failures per email (20 per IP) for 15 minutes. Changing or resetting a password ends all other sessions.
- Scans only reach public addresses: the IP is checked once and every connection is pinned to it (no DNS rebinding).
- The API and website send the same security headers SecureSphere checks for.
- SecureSphere analyses configuration only. It is not a penetration-testing tool, and a high score is not a guarantee of security.
