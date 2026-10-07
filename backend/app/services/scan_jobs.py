"""Module 7b: Background scans. A scan takes 5-60 seconds, so the browser starts a job, then asks
every second how far it is. Jobs live in memory: they only matter while the user is waiting, and a
finished scan is saved in the database anyway."""
import asyncio
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from app.services.scan_service import perform_scan

log = logging.getLogger("securesphere.jobs")
JOBS: dict[str, dict] = {}
_TASKS: set[asyncio.Task] = set()  # keep a reference so running tasks are not garbage-collected
KEEP_FOR = timedelta(hours=1)


def _cleanup() -> None:
    cutoff = datetime.now(timezone.utc) - KEEP_FOR
    for job_id in [j for j, job in JOBS.items() if job["created_at"] < cutoff]:
        JOBS.pop(job_id, None)


def running_count(user_id: str) -> int:
    return sum(1 for j in JOBS.values() if j["user_id"] == user_id and j["status"] == "running")


def start_job(user_id: str, domain: str) -> dict:
    _cleanup()
    job = {"id": secrets.token_urlsafe(12), "user_id": user_id, "domain": domain, "status": "running",
           "steps": [], "scan": None, "error": None, "created_at": datetime.now(timezone.utc)}
    JOBS[job["id"]] = job
    task = asyncio.create_task(_run(job))
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
    return job


async def _run(job: dict) -> None:
    try:
        # list.append is thread-safe, so scanner threads can report finished steps directly.
        job["scan"] = await perform_scan(job["user_id"], job["domain"], source="manual", progress=job["steps"].append)
        job["status"] = "done"
    except HTTPException as e:
        job["status"], job["error"] = "error", e.detail
    except Exception:
        log.exception("Scan job failed for %s", job["domain"])
        job["status"], job["error"] = "error", "Something went wrong during the scan. Please try again."
