"""Module 8b: Alert rules. A pure function: compares two scans and decides what to report.
No database or network access here, so it is easy to unit test and easy to explain."""
from app.config import SCORE_DROP_THRESHOLD


def evaluate(prev: dict | None, new: dict, alerted_expiry: int | None):
    """Returns (alerts, new_expiry_state).
    alerted_expiry remembers which expiry warning was already sent (None, 30 or 7),
    so the same warning is not repeated every day."""
    alerts: list[dict] = []
    state = alerted_expiry

    days = (new.get("certificate") or {}).get("days_left")
    if days is not None:
        if days > 30:
            state = None  # certificate was renewed, reset
        elif days <= 7 and state != 7:
            alerts.append({"type": "certificate_expiry", "severity": "critical",
                           "message": f"Certificate expires in {days} days"})
            state = 7
        elif 7 < days <= 30 and state is None:
            alerts.append({"type": "certificate_expiry", "severity": "warning",
                           "message": f"Certificate expires in {days} days"})
            state = 30

    if prev:
        old_ids = {f["id"] for f in prev.get("findings", [])}
        for f in new.get("findings", []):
            if f["id"] not in old_ids and f.get("severity") in ("high", "critical"):
                alerts.append({"type": "new_weakness", "severity": f["severity"],
                               "message": f"New issue detected: {f['id']}"})
        drop = prev.get("score", 0) - new.get("score", 0)
        if drop >= SCORE_DROP_THRESHOLD:
            alerts.append({"type": "score_drop", "severity": "high",
                           "message": f"Security score dropped from {prev['score']} to {new['score']}"})

    return alerts, state
