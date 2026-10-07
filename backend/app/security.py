"""Module 4: Passwords (bcrypt), login tokens (JWT) and the 'who is calling?' check."""
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from bson import ObjectId
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import JWT_ALGORITHM, JWT_EXPIRE_MINUTES, JWT_SECRET
from app.database import db

bearer = HTTPBearer()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode()[:72], password_hash.encode())


def create_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),  # lets us reject tokens issued before a password change
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    """Dependency: add it to any route that needs a logged-in user."""
    try:
        data = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"_id": ObjectId(data["sub"])})
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    if not user:
        raise HTTPException(401, "User no longer exists")
    # A password change or reset logs out every session that existed before it.
    changed = user.get("password_changed_at")
    if changed and data.get("iat", 0) < int(changed.timestamp()):
        raise HTTPException(401, "Your password was changed. Please log in again.")
    return user


async def verified_user(user: dict = Depends(current_user)) -> dict:
    """Dependency for actions that need a confirmed email (scanning, monitoring, the assistant).
    Anyone can type any address at sign-up; only clicking the emailed link proves it is theirs."""
    if not user.get("email_verified"):
        raise HTTPException(403, "Please confirm your email address first. Check your inbox for our link, "
                                 "or send a new one from the banner at the top of the page.")
    return user
