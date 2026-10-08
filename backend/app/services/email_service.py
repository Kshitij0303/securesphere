"""Module 8a: Sends email through Brevo's web API (if BREVO_API_KEY is set) or SMTP.
Does nothing if neither is configured."""
import json
import logging
import smtplib
import urllib.request
from email.message import EmailMessage

from app.config import BREVO_API_KEY, SMTP_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USER

log = logging.getLogger("securesphere.email")
BREVO_URL = "https://api.brevo.com/v3/smtp/email"


def _send_brevo(to: str, subject: str, body: str) -> None:
    payload = {"sender": {"name": "SecureSphere", "email": SMTP_FROM or SMTP_USER}, "to": [{"email": to}],
               "subject": subject, "textContent": body}
    req = urllib.request.Request(BREVO_URL, data=json.dumps(payload).encode(), method="POST",
                                 headers={"api-key": BREVO_API_KEY, "content-type": "application/json",
                                          "accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15):
        pass  # any non-2xx answer raises HTTPError


def _send_smtp(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = SMTP_FROM or SMTP_USER
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)


def send_email(to: str, subject: str, body: str) -> bool:
    if not BREVO_API_KEY and not SMTP_HOST:
        log.info("SMTP not configured; skipping email to %s", to)
        return False
    try:
        (_send_brevo if BREVO_API_KEY else _send_smtp)(to, subject, body)
        return True
    except Exception:
        log.exception("Could not send email to %s", to)
        return False
