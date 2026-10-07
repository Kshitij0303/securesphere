"""Module 10: Run a scan (directly or as a background job with progress) and read past scans."""
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query

from app.config import MAX_MANUAL_SCANS_PER_HOUR, MAX_RUNNING_SCANS_PER_USER
from app.database import db, serialize
from app.models import ScanIn
from app.security import current_user, verified_user
from app.services import scan_jobs
from app.services.scan_service import perform_scan
from app.utils.validators import clean_domain

router = APIRouter(tags=["scans"])


async def _check_scan_limit(uid: str) -> None:
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    used = await db.scans.count_documents({"user_id": uid, "source": "manual", "scanned_at": {"$gte": since}})
    if used + scan_jobs.running_count(uid) >= MAX_MANUAL_SCANS_PER_HOUR:
        raise HTTPException(429, "Scan limit reached for this hour. Please try again later.")


@router.post("/scan")
async def scan(body: ScanIn, user: dict = Depends(verified_user)):
    """Scans and waits for the result (simple clients, tests). The website uses /scan/jobs instead."""
    uid = str(user["_id"])
    await _check_scan_limit(uid)
    return serialize(await perform_scan(uid, body.domain, source="manual"))


@router.post("/scan/jobs", status_code=202)
async def start_scan_job(body: ScanIn, user: dict = Depends(verified_user)):
    uid = str(user["_id"])
    domain = clean_domain(body.domain)  # reject bad input now, not after the job started
    if scan_jobs.running_count(uid) >= MAX_RUNNING_SCANS_PER_USER:
        raise HTTPException(429, "Please wait for your current scan to finish.")
    await _check_scan_limit(uid)
    job = scan_jobs.start_job(uid, domain)
    return {"job_id": job["id"], "domain": domain}


@router.get("/scan/jobs/{job_id}")
async def scan_job_status(job_id: str, user: dict = Depends(current_user)):
    job = scan_jobs.JOBS.get(job_id)
    if not job or job["user_id"] != str(user["_id"]):
        raise HTTPException(404, "Scan job not found")
    return {
        "status": job["status"],  # running | done | error
        "domain": job["domain"],
        "steps": list(job["steps"]),
        "error": job["error"],
        "scan": serialize(job["scan"]) if job["scan"] else None,
    }


@router.get("/history")
async def history(domain: str | None = None, limit: int = Query(50, ge=1, le=200),
                  user: dict = Depends(current_user)):
    query = {"user_id": str(user["_id"])}
    if domain:
        query["domain"] = domain.strip().lower()
    fields = {"domain": 1, "scanned_at": 1, "score": 1, "grade": 1, "source": 1}
    cursor = db.scans.find(query, fields).sort("scanned_at", -1).limit(limit)
    return [serialize(d) async for d in cursor]


async def _own_scan(scan_id: str, user: dict) -> dict:
    if not ObjectId.is_valid(scan_id):
        raise HTTPException(404, "Scan not found")
    doc = await db.scans.find_one({"_id": ObjectId(scan_id), "user_id": str(user["_id"])})
    if not doc:
        raise HTTPException(404, "Scan not found")
    return doc


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, user: dict = Depends(current_user)):
    return serialize(await _own_scan(scan_id, user))


def _finding_list(ids, scan: dict) -> list[dict]:
    by_id = {f["id"]: f for f in scan.get("findings", [])}
    titles = scan.get("explanations") or {}
    return [{"id": i, "severity": by_id[i].get("severity"), "title": (titles.get(i) or {}).get("title") or i}
            for i in ids]


@router.get("/scan/{scan_id}/compare")
async def compare_with_previous(scan_id: str, user: dict = Depends(current_user)):
    """What changed since the user's previous scan of the same domain."""
    current = await _own_scan(scan_id, user)
    previous = await db.scans.find_one(
        {"user_id": str(user["_id"]), "domain": current["domain"], "scanned_at": {"$lt": current["scanned_at"]}},
        sort=[("scanned_at", -1)],
    )
    if not previous:
        return {"previous": None}
    now_ids = [f["id"] for f in current.get("findings", [])]
    before_ids = [f["id"] for f in previous.get("findings", [])]
    return {
        "previous": {"id": str(previous["_id"]), "score": previous.get("score"), "scanned_at": previous["scanned_at"]},
        "score_change": (current.get("score") or 0) - (previous.get("score") or 0),
        "new_findings": _finding_list([i for i in now_ids if i not in before_ids], current),
        "fixed_findings": _finding_list([i for i in before_ids if i not in now_ids], previous),
    }
