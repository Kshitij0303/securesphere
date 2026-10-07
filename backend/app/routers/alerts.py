"""Module 12: The alerts page (in-app copy of every alert that was emailed)."""
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query

from app.database import db, serialize
from app.security import current_user

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(unread_only: bool = False, limit: int = Query(50, ge=1, le=200),
                      user: dict = Depends(current_user)):
    query = {"user_id": str(user["_id"])}
    if unread_only:
        query["read"] = False
    cursor = db.alerts.find(query).sort("created_at", -1).limit(limit)
    return [serialize(a) async for a in cursor]


@router.get("/unread-count")
async def unread_count(user: dict = Depends(current_user)):
    return {"count": await db.alerts.count_documents({"user_id": str(user["_id"]), "read": False})}


@router.patch("/{alert_id}/read")
async def mark_read(alert_id: str, user: dict = Depends(current_user)):
    if not ObjectId.is_valid(alert_id):
        raise HTTPException(404, "Alert not found")
    res = await db.alerts.update_one(
        {"_id": ObjectId(alert_id), "user_id": str(user["_id"])}, {"$set": {"read": True}}
    )
    if res.matched_count == 0:
        raise HTTPException(404, "Alert not found")
    return {"read": True}
