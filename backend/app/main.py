"""Module 14: Puts everything together. Run with:  uvicorn app.main:app --reload"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.config import CORS_ORIGINS
from app.database import create_indexes
from app.routers import alerts, assistant, auth, monitor, password_reset, scan, users
from app.scheduler import scheduler, start_scheduler

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_indexes()
    start_scheduler()
    yield
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


app.include_router(auth.router)
app.include_router(password_reset.router)
app.include_router(scan.router)
app.include_router(monitor.router)
app.include_router(alerts.router)
app.include_router(users.router)
app.include_router(assistant.router)


@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok"}
