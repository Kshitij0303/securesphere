"""Turns the raw check results into findings and a score out of 100.
These are SecureSphere's own rules, not an industry standard. Results of None (could not test)
never create a finding and never cost points.

Scoring works in three steps:
1. Every finding costs points by severity (stored on the finding as "points_lost").
2. Each category (certificate, protocols, headers, ...) can lose at most a set number of points (CATEGORIES).
3. Some problems are so serious that the score is capped, however good the rest is (like SSL Labs):
   an expired certificate cannot score above 59 (grade F) even if everything else is perfect."""
from urllib.parse import urlsplit

PENALTY = {"critical": 30, "high": 15, "medium": 8, "low": 3}

# Each area of security can lose at most this many points, so one weakness reported in several ways
# (TLS 1.0 and 1.1, a redirect missing on both www and non-www, one cookie missing three flags) cannot
# push a site to 0 on its own. Finding ids are matched by prefix.
CATEGORIES = (
    ("certificate", 40, ("CERT_",)),
    ("vulnerabilities", 30, ("HEARTBLEED", "CCS_INJECTION", "ROBOT_")),
    ("protocols", 25, ("SSL_", "TLS_", "NO_MODERN_TLS", "NO_MODERN_CIPHERS", "WEAK_CIPHERS", "NO_FORWARD_SECRECY")),
    ("enforcement", 20, ("NO_HTTPS_REDIRECT", "HTTPS_NO_PAGE", "HSTS_", "VARIANT_")),
    ("headers", 15, ("CSP_", "X_FRAME", "X_CONTENT", "REFERRER")),
    ("cookies", 10, ("COOKIE_",)),
    ("dns", 3, ("CAA_",)),
)


def category_of(finding_id: str) -> tuple[str, int]:
    for name, limit, prefixes in CATEGORIES:
        if finding_id.startswith(prefixes):
            return name, limit
    return "other", 100

# finding id -> highest score allowed while that finding is present
CAPS = {
    # grade F at best
    "CERT_EXPIRED": 59, "CERT_SELF_SIGNED": 59, "CERT_UNTRUSTED": 59, "CERT_HOSTNAME_MISMATCH": 59,
    "CERT_WEAK_KEY": 59, "NO_MODERN_TLS": 59, "NO_MODERN_CIPHERS": 59, "SSL_2_ENABLED": 59, "SSL_3_ENABLED": 59,
    "HEARTBLEED": 59, "CCS_INJECTION": 59, "ROBOT_VULNERABLE": 59,
    # grade C at best
    "WEAK_CIPHERS": 79, "CERT_WEAK_SIGNATURE": 79, "NO_HTTPS_REDIRECT": 79, "HTTPS_NO_PAGE": 79,
    # grade B at best
    "TLS_1_0_ENABLED": 89, "TLS_1_1_ENABLED": 89,
}


def build_findings(cert: dict, tls: dict, ciphers: dict, headers: dict, redirect: dict, vulns: dict,
                   dns: dict | None = None, variant: dict | None = None) -> list[dict]:
    """tls uses the shared keys ("ssl2", "ssl3", "1.0".."1.3"); headers is the full result of check_headers."""
    dns, variant = dns or {}, variant or {}
    findings: list[dict] = []

    def add(fid: str, severity: str, evidence: str) -> None:
        findings.append({"id": fid, "severity": severity, "evidence": evidence})

    # Certificate
    days, err = cert.get("days_left"), cert.get("error")
    if cert.get("expired"):
        add("CERT_EXPIRED", "critical", f"Certificate expired on {cert['expires_at']}")
    elif days is not None and days <= 7:
        add("CERT_EXPIRES_VERY_SOON", "high", f"Certificate expires in {days} days ({cert['expires_at']})")
    elif days is not None and days <= 14:
        # Not 30: auto-renewed certificates (Let's Encrypt, Google, ...) are normally renewed with ~30 days left.
        add("CERT_EXPIRES_SOON", "medium", f"Certificate expires in {days} days ({cert['expires_at']})")
    if cert.get("domain_match") is False:
        names = ", ".join(cert.get("names", [])[:5]) or "other names"
        add("CERT_HOSTNAME_MISMATCH", "critical", f"The certificate is for {names}, not this domain")
    if err == "self_signed":
        add("CERT_SELF_SIGNED", "critical", "The certificate is self-signed")
    elif err in ("untrusted_root", "untrusted_issuer", "untrusted"):
        add("CERT_UNTRUSTED", "critical", f"Browsers do not trust the certificate issuer ({cert.get('issuer')})")
    elif err == "chain_incomplete":
        add("CERT_CHAIN_INCOMPLETE", "medium", "The server does not send its intermediate certificate")
    if cert.get("weak_key"):
        add("CERT_WEAK_KEY", "high", f"Certificate key is only {cert['key_size']}-bit {cert['key_type']}")
    if cert.get("weak_signature"):
        where = " and ".join(cert.get("weak_signature_in") or ["certificate"])
        add("CERT_WEAK_SIGNATURE", "high", f"The {where} is signed with SHA-1 or MD5")

    # Protocol versions
    if tls.get("ssl2") is True:
        add("SSL_2_ENABLED", "critical", "Server accepts SSL 2.0")
    if tls.get("ssl3") is True:
        add("SSL_3_ENABLED", "critical", "Server accepts SSL 3.0")
    if tls.get("1.0") is True:
        add("TLS_1_0_ENABLED", "high", "Server accepts TLS 1.0")
    if tls.get("1.1") is True:
        add("TLS_1_1_ENABLED", "high", "Server accepts TLS 1.1")
    if cert.get("fetched_with") == "sslyze":
        # Not even a modern TLS library with every cipher it still has could connect; only sslyze's old one
        # could. So the server accepts nothing but encryption browsers have removed (e.g. RC4).
        add("NO_MODERN_CIPHERS", "critical", "The server only accepts encryption methods that modern browsers have removed (such as RC4)")
    if tls.get("1.2") is False and tls.get("1.3") is False:
        add("NO_MODERN_TLS", "critical", "Server supports neither TLS 1.2 nor TLS 1.3")
    elif tls.get("1.3") is False:
        add("TLS_1_3_NOT_SUPPORTED", "low", "Server does not support TLS 1.3")

    # Ciphers
    if ciphers.get("weak"):
        shown = ", ".join(ciphers["weak"][:5]) + (" and more" if len(ciphers["weak"]) > 5 else "")
        add("WEAK_CIPHERS", "high", f"Server accepts {len(ciphers['weak'])} weak cipher(s): {shown}")
    if ciphers.get("forward_secrecy") is False:
        add("NO_FORWARD_SECRECY", "medium", f"Default cipher {ciphers.get('negotiated')} has no forward secrecy")

    # Known vulnerabilities (sslyze)
    if vulns.get("heartbleed"):
        add("HEARTBLEED", "critical", "Server is vulnerable to Heartbleed (CVE-2014-0160)")
    if vulns.get("ccs_injection"):
        add("CCS_INJECTION", "high", "Server is vulnerable to OpenSSL CCS injection (CVE-2014-0224)")
    if vulns.get("robot"):
        add("ROBOT_VULNERABLE", "high", "Server is vulnerable to the ROBOT attack on RSA key exchange")

    # HTTP -> HTTPS redirect
    if redirect.get("http_open") and redirect.get("redirects_to_https") is False:
        if redirect.get("location"):
            add("NO_HTTPS_REDIRECT", "high", f"http:// sends visitors to {redirect['location']}, which is still plain HTTP, not https://")
        else:
            add("NO_HTTPS_REDIRECT", "high", "http:// shows the page without encryption instead of redirecting to https://")

    # Headers
    present, details = headers.get("headers", {}), headers.get("details", {})
    if details.get("https_no_page"):
        add("HTTPS_NO_PAGE", "high", "The server accepts a secure connection but closes it without sending any page")
    if present.get("hsts") is False:
        add("HSTS_MISSING", "medium", "Strict-Transport-Security header absent or invalid")
    elif details.get("hsts_max_age_too_short"):
        add("HSTS_SHORT_MAX_AGE", "low", f"HSTS max-age is {details['hsts_max_age']} seconds (less than 6 months)")
    if present.get("csp") is False:
        if details.get("csp_report_only"):
            add("CSP_REPORT_ONLY", "medium", "Content-Security-Policy is only sent as Report-Only, so nothing is blocked")
        else:
            add("CSP_MISSING", "medium", "Content-Security-Policy header absent")
    elif details.get("csp_weaknesses"):
        add("CSP_UNSAFE_DIRECTIVES", "low", "CSP allows " + ", ".join(f"'{w}'" for w in details["csp_weaknesses"]))
    for key, (fid, severity, header) in {
        "x_frame_options": ("X_FRAME_OPTIONS_MISSING", "low", "X-Frame-Options"),
        "x_content_type_options": ("X_CONTENT_TYPE_OPTIONS_MISSING", "low", "X-Content-Type-Options"),
        "referrer_policy": ("REFERRER_POLICY_MISSING", "low", "Referrer-Policy"),
    }.items():
        if present.get(key) is False:
            add(fid, severity, f"{header} header absent")

    # Cookies
    cookies = headers.get("cookies", [])
    for fid, severity, test, flag in (
        ("COOKIE_NOT_SECURE", "medium", lambda c: not c["secure"], "Secure"),
        ("COOKIE_NO_HTTPONLY", "low", lambda c: not c["httponly"], "HttpOnly"),
        ("COOKIE_NO_SAMESITE", "low", lambda c: not c["samesite"], "SameSite"),
    ):
        bad = [c["name"] for c in cookies if test(c)]
        if bad:
            add(fid, severity, f"{len(bad)} cookie(s) without the {flag} flag: {', '.join(bad[:5])}")

    # DNS (DNSSEC and HSTS preload are shown for information only; most sites have neither)
    if (dns.get("caa") or {}).get("present") is False:
        add("CAA_MISSING", "low", "No CAA record: any certificate authority may issue certificates for this domain")

    # The other name (www / bare domain)
    if variant.get("exists"):
        other = variant["host"]
        if variant.get("https_ok") is False:
            add("VARIANT_NO_HTTPS", "medium", f"{other} exists but does not serve HTTPS")
        elif variant.get("cert_valid") is False:
            add("VARIANT_CERT_INVALID", "high", f"{other} has a certificate that browsers reject")
        elif variant.get("chain_incomplete"):
            add("VARIANT_CERT_CHAIN_INCOMPLETE", "low", f"{other} does not send its intermediate certificate")
        # Skip when the main finding already covers it: http://example.com -> http://www.example.com (still HTTP)
        already_reported = urlsplit(redirect.get("location") or "").hostname == other
        if variant.get("redirects_to_https") is False and not already_reported:
            add("VARIANT_NO_HTTPS_REDIRECT", "medium", f"http://{other} does not redirect to https://")

    return findings


PARTIAL_RESULT_MAX = 89  # an A needs every check to have run


def calculate_score(findings: list[dict], untested: list[str] | None = None) -> tuple[int, str, dict | None]:
    """Returns (score, grade, cap). cap explains when a serious finding limited the score.

    Most serious findings are charged first; once a category reaches its limit, further findings in it
    cost nothing more. points_lost on each finding is what it really cost, so the list adds up to the score."""
    used: dict[str, int] = {}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda f: order[f["severity"]]):
        name, limit = category_of(f["id"])
        f["category"] = name
        f["points_lost"] = min(PENALTY[f["severity"]], limit - used.get(name, 0))
        used[name] = used.get(name, 0) + f["points_lost"]
    score = max(0, 100 - sum(f["points_lost"] for f in findings))

    cap = None
    capping = [(CAPS[f["id"]], f) for f in findings if f["id"] in CAPS]
    if capping:
        limit, finding = min(capping, key=lambda pair: pair[0])
        if score > limit:
            score = limit
            cap = {"max_score": limit, "finding": finding["id"], "reason": finding["evidence"]}
    # A site we could not fully check must not look perfect: the missing checks might have found problems.
    if untested and score > PARTIAL_RESULT_MAX:
        score = PARTIAL_RESULT_MAX
        cap = {"max_score": PARTIAL_RESULT_MAX, "finding": None,
               "reason": "Some checks could not run, and an A needs a complete scan"}

    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return score, grade, cap
