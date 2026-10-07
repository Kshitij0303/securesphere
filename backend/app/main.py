"""Module 14: Puts everything together. Run with:  uvicorn app.main:app --reload"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pymongo.errors import PyMongoError

from app.config import CORS_ORIGINS
from app import database
from app.database import create_indexes
from app.routers import alerts, assistant, auth, monitor, password_reset, scan, users
from app.scheduler import scheduler, start_scheduler

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("securesphere")


async def _prepare_database() -> None:
    """Create the indexes; if the database is down, keep retrying in the background instead of refusing to
    start (a short database hiccup during a restart must not take the whole site down)."""
    while True:
        try:
            await create_indexes()
            log.info("Database ready")
            return
        except PyMongoError as e:
            log.error("Database not reachable (%s); retrying in 30 s", type(e).__name__)
            await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup = asyncio.create_task(_prepare_database())
    start_scheduler()
    yield
    setup.cancel()
    scheduler.shutdown(wait=False)


app = FastAPI(title="SecureSphere API", version="1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# The API only returns JSON, so it can use the strictest policy. The interactive docs page (/docs)
# loads its scripts and styles from a CDN, so it gets a policy that allows exactly that.
API_CSP = "default-src 'none'; frame-ancestors 'none'"
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
            "frame-ancestors 'none'")
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """SecureSphere follows its own advice: every response carries the headers it checks for."""
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    is_docs = request.url.path.startswith(DOCS_PATHS)
    response.headers["Content-Security-Policy"] = DOCS_CSP if is_docs else API_CSP
    if not is_docs:
        response.headers["Cache-Control"] = "no-store"  # API answers contain personal data
    return response


@app.exception_handler(PyMongoError)
async def database_unavailable(request: Request, exc: PyMongoError):
    log.error("Database error on %s %s: %s", request.method, request.url.path, type(exc).__name__)
    return JSONResponse(status_code=503, content={
        "detail": "The database is not reachable right now. Please try again in a minute."})


app.include_router(auth.router)
app.include_router(password_reset.router)
app.include_router(scan.router)
app.include_router(monitor.router)
app.include_router(alerts.router)
app.include_router(users.router)
app.include_router(assistant.router)


@app.get("/health", tags=["system"])
async def health():
    """Always 200 while the server runs (the host restarts it otherwise); says whether the database answers."""
    try:
        await asyncio.wait_for(database.db.command("ping"), timeout=3)
        db_state = "ok"
    except Exception:
        db_state = "unreachable"
    return {"status": "ok", "database": db_state}
