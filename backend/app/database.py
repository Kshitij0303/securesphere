"""Module 2: Database connection (MongoDB via Motor) and indexes."""
from motor.motor_asyncio import AsyncIOMotorClient

from app.config import DB_NAME, MONGO_URL, UNVERIFIED_ACCOUNT_DAYS

# Give up after 5 s (default 30 s): a database outage must answer quickly with a clear error, not hang.
client = AsyncIOMotorClient(MONGO_URL, tz_aware=True, serverSelectionTimeoutMS=5000)
db = client[DB_NAME]


async def create_indexes() -> None:
    await db.users.create_index("email", unique=True)
    # Accounts whose email was never confirmed are deleted by MongoDB after a few days (fake sign-ups clean
    # themselves up). The filter matches only email_verified == false, so confirmed accounts are never touched.
    await db.users.create_index("created_at", name="unverified_expiry",
                                expireAfterSeconds=UNVERIFIED_ACCOUNT_DAYS * 86400,
                                partialFilterExpression={"email_verified": False})
    await db.scans.create_index([("user_id", 1), ("domain", 1), ("scanned_at", -1)])
    await db.monitors.create_index([("user_id", 1), ("domain", 1)], unique=True)
    await db.alerts.create_index([("user_id", 1), ("created_at", -1)])
    await db.scans.create_index([("domain", 1), ("scanned_at", -1)])  # recent-result cache
    await db.password_resets.create_index("token_hash", unique=True)
    await db.password_resets.create_index("expires_at", expireAfterSeconds=0)  # MongoDB deletes expired links
    await db.email_verifications.create_index("token_hash", unique=True)
    await db.email_verifications.create_index("expires_at", expireAfterSeconds=0)
    # Failed logins and assistant usage are only needed for a short while; MongoDB removes them after a day.
    await db.login_failures.create_index([("email", 1), ("created_at", -1)])
    await db.login_failures.create_index([("ip", 1), ("created_at", -1)])
    await db.login_failures.create_index("created_at", expireAfterSeconds=86400)
    await db.assistant_usage.create_index([("user_id", 1), ("created_at", -1)])
    await db.assistant_usage.create_index("created_at", expireAfterSeconds=86400)


def serialize(doc: dict | None) -> dict | None:
    """Turn a MongoDB document into something JSON can carry (_id -> id)."""
    if doc is None:
        return None
    doc = dict(doc)
    doc["id"] = str(doc.pop("_id"))
    return doc
