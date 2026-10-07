"""Module 7: The scan pipeline. Validate -> (reuse a fresh result) -> scan -> explain -> save."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Callable

from fastapi import HTTPException

from app.config import SCAN_CACHE_SECONDS, SCAN_TIMEOUT_SECONDS
from app.database import db
from app.scanner_adapter import explain_findings, run_scan
from app.utils.validators import assert_public, clean_domain

log = logging.getLogger("securesphere.scan")

# Fields that belong to one user's copy of a scan, not to the scan result itself.
OWNER_FIELDS = ("_id", "user_id", "source", "cached", "cached_from")


async def _recent_result(domain: str) -> dict | None:
    """A scan of the same domain (by anyone) from the last few minutes; the result would be identical."""
    since = datetime.now(timezone.utc) - timedelta(seconds=SCAN_CACHE_SECONDS)
    return await db.scans.find_one({"domain": domain, "scanned_at": {"$gte": since}, "cached": {"$ne": True}},
                                   sort=[("scanned_at", -1)])


async def perform_scan(user_id: str, raw_domain: str, source: str = "manual",
                       progress: Callable[[str], None] | None = None) -> dict:
    domain = clean_domain(raw_domain)

    if source == "manual" and SCAN_CACHE_SECONDS > 0:
        recent = await _recent_result(domain)
        if recent:
            doc = {k: v for k, v in recent.items() if k not in OWNER_FIELDS}
            doc.update(user_id=user_id, source=source, cached=True, cached_from=str(recent["_id"]))
            res = await db.scans.insert_one(doc)
            doc["_id"] = res.inserted_id
            if progress:
                progress("cached")
            return doc

    ip = await asyncio.to_thread(assert_public, domain)

    # The scanner is blocking code, so it runs in a worker thread to keep the API responsive.
    try:
        result = await asyncio.wait_for(asyncio.to_thread(run_scan, domain, ip=ip, progress=progress),
                                        SCAN_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise HTTPException(504, "The scan took too long. Please try again later.")
    except Exception:
        log.exception("Scan failed for %s", domain)
        raise HTTPException(502, "Could not scan this site. It may be unreachable or not serving HTTPS.")

    # Only real findings are explained; anything returned for an unknown id is thrown away.
    findings = result.get("findings", [])
    explanations: dict = {}
    if findings:
        try:
            raw = await asyncio.to_thread(explain_findings, findings)
            valid_ids = {f["id"] for f in findings}
            explanations = {k: v for k, v in raw.items() if k in valid_ids}
        except Exception:
            log.exception("Explanation failed for %s", domain)  # scan is still saved without it

    doc = {
        "user_id": user_id,
        "domain": domain,
        "source": source,
        "scanned_at": datetime.now(timezone.utc),
        **result,
        "explanations": explanations,
    }
    res = await db.scans.insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc
