"""Module 9: Sign-up, login (with brute-force protection) and email verification."""
import asyncio
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pymongo.errors import DuplicateKeyError

from app.config import LOGIN_LOCK_MINUTES, MAX_FAILED_LOGINS, MAX_FAILED_LOGINS_PER_IP
from app.database import db
from app.models import LoginIn, SignupIn, TokenOut, VerifyEmailIn
from app.security import create_token, hash_password, verify_password
from app.services.tokens import hash_token
from app.services.verification import send_verification
from app.utils.validators import email_domain_accepts_mail

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=TokenOut, status_code=201)
async def signup(body: SignupIn, background: BackgroundTasks):
    if not await asyncio.to_thread(email_domain_accepts_mail, body.email):
        domain = body.email.rsplit("@", 1)[-1]
        raise HTTPException(400, f"We can't send email to {domain}. Please check your email address.")
    user = {
        "name": body.name.strip(),
        "email": body.email.lower(),
        "password_hash": hash_password(body.password),
        "email_verified": False,
        "created_at": datetime.now(timezone.utc),
    }
    try:
        res = await db.users.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(409, "This email is already registered")
    user["_id"] = res.inserted_id
    background.add_task(send_verification, user)  # sending email must not slow down sign-up
    return TokenOut(access_token=create_token(str(res.inserted_id)))


@router.post("/login", response_model=TokenOut)
async def login(body: LoginIn, request: Request):
    email = body.email.lower()
    ip = request.client.host if request.client else "unknown"
    since = datetime.now(timezone.utc) - timedelta(minutes=LOGIN_LOCK_MINUTES)
    # Lock by email (guessing one account) and by IP address (trying many accounts).
    if (await db.login_failures.count_documents({"email": email, "created_at": {"$gte": since}}) >= MAX_FAILED_LOGINS
            or await db.login_failures.count_documents({"ip": ip, "created_at": {"$gte": since}}) >= MAX_FAILED_LOGINS_PER_IP):
        raise HTTPException(429, f"Too many failed login attempts. Please try again in {LOGIN_LOCK_MINUTES} minutes "
                                 "or reset your password.")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user["password_hash"]):
        await db.login_failures.insert_one({"email": email, "ip": ip, "created_at": datetime.now(timezone.utc)})
        raise HTTPException(401, "Incorrect email or password")  # same message for both cases

    await db.login_failures.delete_many({"email": email})
    return TokenOut(access_token=create_token(str(user["_id"])))


@router.post("/verify-email")
async def verify_email(body: VerifyEmailIn):
    now = datetime.now(timezone.utc)
    record = await db.email_verifications.find_one_and_update(
        {"token_hash": hash_token(body.token), "used": False, "expires_at": {"$gt": now}},
        {"$set": {"used": True, "used_at": now}},
    )
    if not record:
        raise HTTPException(400, "This verification link is invalid or has expired. Ask for a new one on your profile page.")
    # Only verify if the account still has the email the link was sent to.
    await db.users.update_one({"_id": ObjectId(record["user_id"]), "email": record["email"]},
                              {"$set": {"email_verified": True, "email_verified_at": now}})
    return {"message": "Your email address is confirmed."}
