"""Module 13: The daily rescan job (APScheduler)."""
import asyncio
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from bson import ObjectId

from app.config import SCAN_HOUR, SCHEDULER_TZ
from app.database import db
from app.services.alert_service import evaluate
from app.services.email_service import send_email
from app.services.scan_service import perform_scan

log = logging.getLogger("securesphere.scheduler")
scheduler = AsyncIOScheduler(timezone=SCHEDULER_TZ)


async def rescan_one(mon: dict) -> None:
    # Fetch the previous scan BEFORE saving the new one, so we compare old vs new.
    prev = await db.scans.find_one(
        {"user_id": mon["user_id"], "domain": mon["domain"]}, sort=[("scanned_at", -1)]
    )
    new = await perform_scan(mon["user_id"], mon["domain"], source="scheduled")
    alerts, state = evaluate(prev, new, mon.get("alerted_expiry"))

    if alerts:
        now = datetime.now(timezone.utc)
        await db.alerts.insert_many([
            {**a, "user_id": mon["user_id"], "domain": mon["domain"],
             "scan_id": str(new["_id"]), "created_at": now, "read": False}
            for a in alerts
        ])
        user = await db.users.find_one({"_id": ObjectId(mon["user_id"])})
        if user and user.get("email_verified"):  # never email an address nobody confirmed
            body = "\n".join(f"- {a['message']}" for a in alerts)
            body += f"\n\nDomain: {mon['domain']}\nCurrent score: {new['score']}/100"
            await asyncio.to_thread(send_email, user["email"], f"SecureSphere alert: {mon['domain']}", body)

    await db.monitors.update_one(
        {"_id": mon["_id"]},
        {"$set": {"alerted_expiry": state, "last_score": new["score"], "last_scanned_at": new["scanned_at"]}},
    )


async def rescan_all() -> None:
    log.info("Daily rescan started")
    async for mon in db.monitors.find({"active": True}):
        try:
            await rescan_one(mon)
        except Exception:  # one failing site must not stop the others
            log.exception("Rescan failed for %s", mon.get("domain"))
    log.info("Daily rescan finished")


def start_scheduler() -> None:
    scheduler.add_job(rescan_all, CronTrigger(hour=SCAN_HOUR, minute=0, timezone=SCHEDULER_TZ), id="daily_rescan",
                      replace_existing=True, max_instances=1, coalesce=True)
    scheduler.start()
