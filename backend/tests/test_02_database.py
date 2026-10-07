import pytest
from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from app.database import db, serialize


def test_serialize_converts_id():
    oid = ObjectId()
    out = serialize({"_id": oid, "x": 1})
    assert out == {"id": str(oid), "x": 1}


def test_serialize_none():
    assert serialize(None) is None


async def test_duplicate_email_rejected():
    await db.users.insert_one({"email": "a@b.com"})
    with pytest.raises(DuplicateKeyError):
        await db.users.insert_one({"email": "a@b.com"})


async def test_duplicate_monitor_per_user_rejected_but_other_user_ok():
    await db.monitors.insert_one({"user_id": "u1", "domain": "x.com"})
    await db.monitors.insert_one({"user_id": "u2", "domain": "x.com"})  # different user: fine
    with pytest.raises(DuplicateKeyError):
        await db.monitors.insert_one({"user_id": "u1", "domain": "x.com"})
