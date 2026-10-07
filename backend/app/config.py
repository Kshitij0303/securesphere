"""Module 1: Configuration. Every setting is read from the environment (.env file)."""
import os

from dotenv import load_dotenv

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "securesphere")

JWT_SECRET = os.getenv("JWT_SECRET", "")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set. Add it to your .env file.")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")]

SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "60"))
MAX_MANUAL_SCANS_PER_HOUR = int(os.getenv("MAX_MANUAL_SCANS_PER_HOUR", "20"))
MAX_RUNNING_SCANS_PER_USER = int(os.getenv("MAX_RUNNING_SCANS_PER_USER", "2"))
SCAN_CACHE_SECONDS = int(os.getenv("SCAN_CACHE_SECONDS", "300"))  # reuse a fresh result of the same domain

# Login protection: after this many failed logins the email (or IP address) is locked for a while.
MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "5"))
MAX_FAILED_LOGINS_PER_IP = int(os.getenv("MAX_FAILED_LOGINS_PER_IP", "20"))
LOGIN_LOCK_MINUTES = int(os.getenv("LOGIN_LOCK_MINUTES", "15"))

SCORE_DROP_THRESHOLD = int(os.getenv("SCORE_DROP_THRESHOLD", "10"))
SCHEDULER_TZ = os.getenv("SCHEDULER_TZ", "Asia/Kolkata")
SCAN_HOUR = int(os.getenv("SCAN_HOUR", "2"))

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
RESET_TOKEN_MINUTES = int(os.getenv("RESET_TOKEN_MINUTES", "30"))
MAX_RESET_REQUESTS_PER_HOUR = int(os.getenv("MAX_RESET_REQUESTS_PER_HOUR", "3"))
VERIFY_TOKEN_HOURS = int(os.getenv("VERIFY_TOKEN_HOURS", "24"))
UNVERIFIED_ACCOUNT_DAYS = int(os.getenv("UNVERIFIED_ACCOUNT_DAYS", "3"))  # then deleted automatically

# AI assistant (Claude). Without ANTHROPIC_API_KEY the frontend uses its simple built-in answers.
ASSISTANT_MODEL = os.getenv("ASSISTANT_MODEL", "claude-opus-5-5")
MAX_ASSISTANT_MESSAGES_PER_HOUR = int(os.getenv("MAX_ASSISTANT_MESSAGES_PER_HOUR", "30"))

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "")
