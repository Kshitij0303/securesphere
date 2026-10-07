"""HTTP -> HTTPS redirect check: does the plain http:// address send visitors to the secure site?

If port 80 is closed, plain HTTP is not offered at all, which is fine. If it is open, it must redirect
to https://. Redirects are followed only within the same site (example.com <-> www.example.com), never to
other hosts, and every new name gets its own public-address check, so this cannot reach other servers."""
import http.client
from urllib.parse import urlsplit

from scanner.net import PinnedHTTPConnection, resolve_public

TIMEOUT = 8
MAX_HOPS = 3
REDIRECT_CODES = (301, 302, 303, 307, 308)


def _same_site(a: str, b: str) -> bool:
    strip = lambda h: h.lower().removeprefix("www.")
    return strip(a) == strip(b)


def check_https_redirect(host: str, ip: str | None = None) -> dict:
    current, current_ip, path = host, ip, "/"
    first_status = None
    for _ in range(MAX_HOPS):
        conn = PinnedHTTPConnection(current, current_ip, TIMEOUT)
        try:
            conn.request("GET", path, headers={"User-Agent": "SecureSphere/1.0 (+security scan)"})
            resp = conn.getresponse()
            status, location = resp.status, resp.getheader("Location") or ""
        except (OSError, http.client.HTTPException):
            if first_status is None:
                return {"http_open": False, "redirects_to_https": None, "status": None, "location": None}
            break
        finally:
            conn.close()

        first_status = first_status or status
        if status not in REDIRECT_CODES:
            break
        target = urlsplit(location)
        if target.scheme == "https":
            return {"http_open": True, "redirects_to_https": True, "status": first_status,
                    "location": location[:200], "permanent": first_status in (301, 308)}
        # http -> http hop (e.g. example.com -> www.example.com): follow it only within the same site
        next_host = target.hostname or current
        if target.scheme not in ("http", "") or not _same_site(next_host, host):
            break
        if next_host != current:
            try:
                current_ip = resolve_public(next_host)
            except ValueError:
                break
        current, path = next_host, (target.path or "/") + (f"?{target.query}" if target.query else "")

    return {"http_open": True, "redirects_to_https": False, "status": first_status, "location": None}
