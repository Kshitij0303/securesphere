"""Module 11: Choose which domains get rescanned every day. The first scan runs right away."""
import asyncio
import logging
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pymongo.errors import DuplicateKeyError

from app.database import db, serialize
from app.models import MonitorIn
from app.scheduler import rescan_one
from app.security import current_user
from app.utils.validators import assert_public, clean_domain

log = logging.getLogger("securesphere.monitor")
router = APIRouter(prefix="/monitor", tags=["monitoring"])


async def _first_scan(mon: dict) -> None:
    try:
        await rescan_one(mon)
    except Exception:
        log.exception("First scan failed for %s", mon["domain"])  # the daily job will try again


@router.post("", status_code=201)
async def add_monitor(body: MonitorIn, background: BackgroundTasks, user: dict = Depends(current_user)):
    domain = clean_domain(body.domain)
    await asyncio.to_thread(assert_public, domain)
    try:
        res = await db.monitors.insert_one({
            "user_id": str(user["_id"]), "domain": domain, "active": True,
            "created_at": datetime.now(timezone.utc),
            "alerted_expiry": None, "last_score": None, "last_scanned_at": None,
        })
    except DuplicateKeyError:
        raise HTTPException(409, "You are already monitoring this domain")
    mon = await db.monitors.find_one({"_id": res.inserted_id})
    background.add_task(_first_scan, mon)  # so the site has a score now, not only after the nightly run
    return serialize(mon)


@router.get("")
async def list_monitors(user: dict = Depends(current_user)):
    cursor = db.monitors.find({"user_id": str(user["_id"])}).sort("created_at", -1)
    return [serialize(m) async for m in cursor]


@router.delete("/{monitor_id}", status_code=204)
async def remove_monitor(monitor_id: str, user: dict = Depends(current_user)):
    if not ObjectId.is_valid(monitor_id):
        raise HTTPException(404, "Monitor not found")
    res = await db.monitors.delete_one({"_id": ObjectId(monitor_id), "user_id": str(user["_id"])})
    if res.deleted_count == 0:
        raise HTTPException(404, "Monitor not found")
