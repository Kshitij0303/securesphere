"""One-time tokens for email links (password reset, email verification).
Only the SHA-256 hash is stored, so a database leak does not leak working links."""
import hashlib
import secrets


def new_token() -> tuple[str, str]:
    """Returns (token for the link, hash for the database)."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
