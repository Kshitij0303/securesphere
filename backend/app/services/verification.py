"""Module 8c: Email verification. New accounts get a link; alert emails go only to verified addresses."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.config import FRONTEND_URL, EMAIL_ENABLED, VERIFY_TOKEN_HOURS
from app.database import db
from app.services.email_service import send_email
from app.services.tokens import new_token

log = logging.getLogger("securesphere.verification")


async def send_verification(user: dict) -> None:
    uid = str(user["_id"])
    now = datetime.now(timezone.utc)
    token, token_hash = new_token()
    await db.email_verifications.update_many({"user_id": uid, "used": False}, {"$set": {"used": True}})
    await db.email_verifications.insert_one({
        "user_id": uid, "email": user["email"], "token_hash": token_hash, "used": False,
        "created_at": now, "expires_at": now + timedelta(hours=VERIFY_TOKEN_HOURS),
    })
    link = f"{FRONTEND_URL}/verify-email?token={token}"
    body = (
        f"Welcome to SecureSphere!\n\nPlease confirm your email address ({user['email']}) so we can send you "
        f"security alerts:\n{link}\n\nThe link expires in {VERIFY_TOKEN_HOURS} hours. "
        "If you did not create an account, ignore this email."
    )
    await asyncio.to_thread(send_email, user["email"], "Confirm your SecureSphere email", body)
    if not EMAIL_ENABLED:
        log.warning("SMTP not configured. Email verification link for %s: %s", user["email"], link)


async def count_recent_requests(user_id: str) -> int:
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    return await db.email_verifications.count_documents({"user_id": user_id, "created_at": {"$gte": since}})
