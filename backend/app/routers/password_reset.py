"""Module 16: Forgot password. Emails a one-time link; the link lets the user choose a new password.

Safety rules:
- The same answer is given whether or not the email has an account, so nobody can probe who is registered.
- Only a SHA-256 hash of the reset token is stored, so a database leak does not leak working links.
- Links expire after RESET_TOKEN_MINUTES and work once. Asking again cancels older links."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from fastapi import APIRouter, HTTPException

from app.config import FRONTEND_URL, MAX_RESET_REQUESTS_PER_HOUR, RESET_TOKEN_MINUTES, SMTP_HOST
from app.database import db
from app.models import ForgotPasswordIn, ResetPasswordIn
from app.security import hash_password
from app.services.email_service import send_email
from app.services.tokens import hash_token, new_token

log = logging.getLogger("securesphere.password_reset")
router = APIRouter(prefix="/auth", tags=["auth"])

GENERIC_REPLY = {"message": "If an account exists for that email, a reset link has been sent."}


@router.post("/forgot-password")
async def forgot_password(body: ForgotPasswordIn):
    user = await db.users.find_one({"email": body.email.lower()})
    if not user:
        return GENERIC_REPLY

    uid = str(user["_id"])
    now = datetime.now(timezone.utc)
    recent = await db.password_resets.count_documents({"user_id": uid, "created_at": {"$gte": now - timedelta(hours=1)}})
    if recent >= MAX_RESET_REQUESTS_PER_HOUR:
        return GENERIC_REPLY  # quietly stop email flooding

    token, token_hash = new_token()
    await db.password_resets.update_many({"user_id": uid, "used": False}, {"$set": {"used": True}})
    await db.password_resets.insert_one({
        "user_id": uid, "token_hash": token_hash, "used": False,
        "created_at": now, "expires_at": now + timedelta(minutes=RESET_TOKEN_MINUTES),
    })

    link = f"{FRONTEND_URL}/reset-password?token={token}"
    body_text = (
        f"Someone asked to reset the password for your SecureSphere account ({user['email']}).\n\n"
        f"Choose a new password here (the link works once and expires in {RESET_TOKEN_MINUTES} minutes):\n{link}\n\n"
        "If you did not ask for this, ignore this email. Your password will not change."
    )
    await asyncio.to_thread(send_email, user["email"], "Reset your SecureSphere password", body_text)
    if not SMTP_HOST:
        # Local development only: with no email server configured, print the link so it can still be tested.
        log.warning("SMTP not configured. Password reset link for %s: %s", user["email"], link)
    return GENERIC_REPLY


@router.post("/reset-password")
async def reset_password(body: ResetPasswordIn):
    now = datetime.now(timezone.utc)
    reset = await db.password_resets.find_one_and_update(
        {"token_hash": hash_token(body.token), "used": False, "expires_at": {"$gt": now}},
        {"$set": {"used": True, "used_at": now}},
    )
    if not reset:
        raise HTTPException(400, "This reset link is invalid or has expired. Please ask for a new one.")
    # Setting password_changed_at logs out every existing session (see security.current_user).
    # Clicking the emailed link also proves the user owns the address, so it counts as verification.
    user = await db.users.find_one_and_update(
        {"_id": ObjectId(reset["user_id"])},
        {"$set": {"password_hash": hash_password(body.new_password), "password_changed_at": now, "email_verified": True}},
    )
    if user:
        await db.login_failures.delete_many({"email": user["email"]})
    return {"message": "Your password has been changed. You can now log in."}
