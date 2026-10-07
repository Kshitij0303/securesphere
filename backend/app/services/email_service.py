"""Module 8a: Sends email through SMTP. Does nothing if SMTP is not configured."""
import logging
import smtplib
from email.message import EmailMessage

from app.config import SMTP_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USER

log = logging.getLogger("securesphere.email")


def send_email(to: str, subject: str, body: str) -> bool:
    if not SMTP_HOST:
        log.info("SMTP not configured; skipping email to %s", to)
        return False
    msg = EmailMessage()
    msg["From"] = SMTP_FROM or SMTP_USER
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception:
        log.exception("Could not send email to %s", to)
        return False
