"""Module 15: The logged-in user's own profile: details, activity summary, name and password changes."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from app.database import db, serialize
from app.models import PasswordChangeIn, ProfileUpdateIn
from app.security import create_token, current_user, hash_password, verify_password
from app.services.verification import count_recent_requests, send_verification

router = APIRouter(prefix="/users", tags=["users"])


def public_profile(user: dict) -> dict:
    """Only the fields that are safe to show. password_hash never leaves the server."""
    return {
        "id": str(user["_id"]),
        "name": user.get("name") or user["email"].split("@")[0],  # older accounts have no name
        "email": user["email"],
        "email_verified": bool(user.get("email_verified")),
        "created_at": user.get("created_at"),
    }


@router.get("/me")
async def me(user: dict = Depends(current_user)):
    uid = str(user["_id"])
    stats = {
        "scans": await db.scans.count_documents({"user_id": uid}),
        "monitors": await db.monitors.count_documents({"user_id": uid}),
        "unread_alerts": await db.alerts.count_documents({"user_id": uid, "read": False}),
    }
    fields = {"domain": 1, "scanned_at": 1, "score": 1, "grade": 1, "source": 1}
    cursor = db.scans.find({"user_id": uid}, fields).sort("scanned_at", -1).limit(5)
    return {**public_profile(user), "stats": stats, "recent_scans": [serialize(s) async for s in cursor]}


@router.patch("/me")
async def update_me(body: ProfileUpdateIn, user: dict = Depends(current_user)):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Name cannot be empty")
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"name": name}})
    return public_profile({**user, "name": name})


@router.post("/me/password")
async def change_password(body: PasswordChangeIn, user: dict = Depends(current_user)):
    if not verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    # password_changed_at logs out all other sessions; this one gets a fresh token so it stays logged in.
    await db.users.update_one({"_id": user["_id"]}, {"$set": {
        "password_hash": hash_password(body.new_password),
        "password_changed_at": datetime.now(timezone.utc),
    }})
    return {"updated": True, "access_token": create_token(str(user["_id"]))}


@router.post("/me/resend-verification")
async def resend_verification(user: dict = Depends(current_user)):
    if user.get("email_verified"):
        raise HTTPException(400, "Your email address is already confirmed.")
    if await count_recent_requests(str(user["_id"])) >= 3:
        raise HTTPException(429, "Too many emails sent. Please wait an hour and try again.")
    await send_verification(user)
    return {"message": f"We sent a new confirmation link to {user['email']}."}
