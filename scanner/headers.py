"""Security header check: load the home page over HTTPS and look at the response headers.

Returns three parts:
  headers  - is each header present AND doing its job? True/False, or None when the page could not be loaded
  details  - quality information: HSTS max-age/includeSubDomains/preload, CSP report-only and unsafe directives
  cookies  - every cookie the page sets, with its Secure / HttpOnly / SameSite flags"""
import http.client
import ssl
from urllib.parse import urlsplit

from scanner.net import PinnedHTTPSConnection, resolve_public

TIMEOUT = 10
MAX_REDIRECTS = 4
USER_AGENT = "SecureSphere/1.0 (+security scan)"
HSTS_MIN_MAX_AGE = 15768000  # 6 months, the usual recommendation

HEADERS = {
    "hsts": "Strict-Transport-Security",
    "csp": "Content-Security-Policy",
    "x_frame_options": "X-Frame-Options",
    "x_content_type_options": "X-Content-Type-Options",
    "referrer_policy": "Referrer-Policy",
}


def _parse_hsts(value: str) -> tuple[int | None, bool, bool]:
    directives = [d.strip().lower() for d in value.split(";") if d.strip()]
    max_age = None
    for d in directives:
        if d.startswith("max-age="):
            try:
                max_age = int(d.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                pass
    return max_age, "includesubdomains" in directives, "preload" in directives


def _csp_weaknesses(value: str) -> list[str]:
    """Unsafe sources for SCRIPTS only. 'unsafe-inline' in style-src (common, needed by many chart
    libraries) is a minor risk and is not reported. script-src falls back to default-src when absent."""
    directives = {}
    for part in value.lower().split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0], tokens[1:])
    v = " ".join(directives.get("script-src", directives.get("default-src", [])))
    found = []
    # Browsers ignore 'unsafe-inline' when a nonce, hash or 'strict-dynamic' is present (a common
    # backwards-compatibility pattern), so it is only a weakness without them.
    has_nonce_or_hash = "'nonce-" in v or "'sha256-" in v or "'sha384-" in v or "'sha512-" in v or "'strict-dynamic'" in v
    if "'unsafe-inline'" in v and not has_nonce_or_hash:
        found.append("unsafe-inline")
    if "'unsafe-eval'" in v:
        found.append("unsafe-eval")
    return found


def _parse_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else "") for p in parts[1:]}
    return {
        "name": parts[0].split("=", 1)[0].strip()[:100],
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": attrs.get("samesite") or None,
    }


def _same_site(a: str, b: str) -> bool:
    strip = lambda h: h.lower().removeprefix("www.")
    return strip(a) == strip(b)


def _fetch_home_page(host: str, ip: str | None):
    """GET https://host/ on the pinned IP and follow redirects that stay on the same site
    (/ -> /en/, example.com -> www.example.com). Returns (headers, final_url)."""
    # Certificate problems are reported by cert.py, so do not let them hide the headers.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    current_host, current_ip, path = host, ip, "/"
    for _ in range(MAX_REDIRECTS + 1):
        conn = PinnedHTTPSConnection(current_host, current_ip, ctx, TIMEOUT)
        try:
            conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
            resp = conn.getresponse()
            headers, status = resp.headers, resp.status
        finally:
            conn.close()
        location = headers.get("Location") or ""
        target = urlsplit(location)
        if status not in (301, 302, 303, 307, 308) or not location or target.scheme == "http":
            break  # a page (any status: 403/404 pages still carry the site's headers), or a downgrade
        next_host = target.hostname or current_host
        if not _same_site(next_host, host):
            break  # never follow redirects to other sites
        if next_host != current_host:
            current_ip = resolve_public(next_host)  # a new name gets its own safety check
        current_host = next_host
        path = (target.path or "/") + (f"?{target.query}" if target.query else "")
    return headers, f"https://{current_host}{path}"


def _blocked_by(found) -> str | None:
    """Firewalls (bot protection) answer automated requests with a challenge page. Its headers are the
    firewall's, not the website's, so reading them would wrongly report every header as missing."""
    if (found.get("X-Vercel-Mitigated") or "").lower() == "challenge":
        return "Vercel bot protection"
    if (found.get("cf-mitigated") or "").lower() == "challenge":
        return "Cloudflare bot protection"
    if found.get("x-amzn-waf-action"):
        return "AWS firewall"
    return None


def check_headers(host: str, ip: str | None = None) -> dict:
    unknown = {key: None for key in HEADERS}
    try:
        found, final_url = _fetch_home_page(host, ip)
    except (OSError, http.client.HTTPException, ValueError):
        return {"headers": unknown, "details": {}, "cookies": []}
    blocker = _blocked_by(found)
    if blocker:
        return {"headers": unknown, "details": {"blocked_by": blocker}, "cookies": []}

    headers = {key: found.get(name) is not None for key, name in HEADERS.items()}

    # HSTS only counts with a valid max-age above 0.
    hsts_value = found.get("Strict-Transport-Security")
    max_age, include_sub, preload = _parse_hsts(hsts_value) if hsts_value else (None, False, False)
    if hsts_value and not max_age:
        headers["hsts"] = False

    # CSP sent only as "report-only" reports problems but blocks nothing.
    csp_value = found.get("Content-Security-Policy") or ""
    report_only = not csp_value and found.get("Content-Security-Policy-Report-Only") is not None

    return {
        "headers": headers,
        "details": {
            "final_url": final_url,
            "hsts_max_age": max_age,
            "hsts_include_subdomains": include_sub,
            "hsts_preload": preload,
            "hsts_max_age_too_short": bool(headers["hsts"] and max_age < HSTS_MIN_MAX_AGE),
            "csp_report_only": report_only,
            "csp_weaknesses": _csp_weaknesses(csp_value) if csp_value else [],
        },
        "cookies": [_parse_cookie(c) for c in (found.get_all("Set-Cookie") or [])][:20],
    }
