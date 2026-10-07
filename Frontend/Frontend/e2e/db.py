"""Test helper for the end-to-end tests: talks to the LOCAL MongoDB only.

    python e2e/db.py verify <email>     mark an account's email as confirmed (no real email is sent in tests)
    python e2e/db.py cleanup <prefix>   delete test accounts whose email starts with <prefix>, and their data"""
import os
import sys

from dotenv import dotenv_values
from pymongo import MongoClient

env = dotenv_values(os.path.join(os.path.dirname(__file__), "..", "..", "..", "backend", ".env"))
url = env.get("MONGO_URL") or "mongodb://localhost:27017"
if "localhost" not in url and "127.0.0.1" not in url:
    sys.exit("Refusing to touch a non-local database")
db = MongoClient(url)[env.get("DB_NAME") or "securesphere"]

command, value = sys.argv[1], sys.argv[2]
if command == "verify":
    db.users.update_one({"email": value.lower()}, {"$set": {"email_verified": True}})
elif command == "cleanup":
    for user in db.users.find({"email": {"$regex": "^" + value}}):
        uid = str(user["_id"])
        for name in ("scans", "monitors", "alerts", "email_verifications", "assistant_usage", "password_resets"):
            db[name].delete_many({"user_id": uid})
        db.users.delete_one({"_id": user["_id"]})
    db.login_failures.delete_many({"email": {"$regex": "^" + value}})
