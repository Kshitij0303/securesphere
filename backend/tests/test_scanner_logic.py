"""Scanner rules that need no network: these must give exactly the expected answers."""
import pytest

from scanner.cert import hostname_matches
from scanner.dns_checks import _candidates
from scanner.explain import EXPLANATIONS, explain_findings
from scanner.headers import _csp_weaknesses, _parse_cookie, _parse_hsts
from scanner.net import resolve_public
from scanner.score import build_findings, calculate_score
from scanner.variant import other_name

GOOD_CERT = {"days_left": 200, "expires_at": "2027-05-01", "expired": False, "domain_match": True, "error": None,
             "names": ["example.com"], "weak_key": False, "weak_signature": False}
GOOD_TLS = {"ssl2": False, "ssl3": False, "1.0": False, "1.1": False, "1.2": True, "1.3": True}
GOOD_CIPHERS = {"weak": [], "forward_secrecy": True, "negotiated": "TLS_AES_128_GCM_SHA256"}
GOOD_HEADERS = {"headers": dict.fromkeys(["hsts", "csp", "x_frame_options", "x_content_type_options", "referrer_policy"], True),
                "details": {"hsts_max_age": 31536000, "csp_weaknesses": []}, "cookies": []}
GOOD_REDIRECT = {"http_open": True, "redirects_to_https": True, "status": 301}
NO_VULNS = {"heartbleed": False, "ccs_injection": False, "robot": False}


def findings_for(**changes):
    parts = {"cert": GOOD_CERT, "tls": GOOD_TLS, "ciphers": GOOD_CIPHERS, "headers": GOOD_HEADERS,
             "redirect": GOOD_REDIRECT, "vulns": NO_VULNS}
    for key, value in changes.items():
        parts[key] = {**parts[key], **value}
    return [f["id"] for f in build_findings(parts["cert"], parts["tls"], parts["ciphers"], parts["headers"],
                                            parts["redirect"], parts["vulns"])]


@pytest.mark.parametrize("host, names, expected", [
    ("example.com", ["example.com"], True),
    ("Example.COM", ["example.com"], True),
    ("a.example.com", ["*.example.com"], True),
    ("example.com", ["*.example.com"], False),        # wildcard does not cover the bare domain
    ("a.b.example.com", ["*.example.com"], False),    # wildcard covers exactly one label
    ("evil-example.com", ["*.example.com"], False),
    ("other.com", ["example.com", "www.example.com"], False),
])
def test_hostname_matching(host, names, expected):
    assert hostname_matches(host, names) is expected


def test_perfect_site_has_no_findings_and_scores_100():
    findings = build_findings(GOOD_CERT, GOOD_TLS, GOOD_CIPHERS, GOOD_HEADERS, GOOD_REDIRECT, NO_VULNS)
    assert findings == []
    assert calculate_score(findings) == (100, "A", None)


def test_untested_values_never_create_findings():
    """None means "could not test" and must never cost points."""
    unknown_tls = dict.fromkeys(GOOD_TLS)
    unknown_headers = {"headers": dict.fromkeys(GOOD_HEADERS["headers"]), "details": {}, "cookies": []}
    findings = build_findings({**GOOD_CERT, "domain_match": None}, unknown_tls, {"weak": [], "forward_secrecy": None},
                              unknown_headers, {"http_open": None}, dict.fromkeys(NO_VULNS))
    assert findings == []


@pytest.mark.parametrize("changes, expected_id", [
    ({"cert": {"expired": True, "days_left": -3}}, "CERT_EXPIRED"),
    ({"cert": {"days_left": 5}}, "CERT_EXPIRES_VERY_SOON"),
    ({"cert": {"days_left": 20}}, "CERT_EXPIRES_SOON"),
    ({"cert": {"domain_match": False}}, "CERT_HOSTNAME_MISMATCH"),
    ({"cert": {"error": "self_signed"}}, "CERT_SELF_SIGNED"),
    ({"cert": {"error": "untrusted_root"}}, "CERT_UNTRUSTED"),
    ({"cert": {"weak_key": True, "key_size": 1024, "key_type": "RSA"}}, "CERT_WEAK_KEY"),
    ({"cert": {"weak_signature": True, "signature_hash": "sha1"}}, "CERT_WEAK_SIGNATURE"),
    ({"tls": {"ssl3": True}}, "SSL_3_ENABLED"),
    ({"tls": {"1.0": True}}, "TLS_1_0_ENABLED"),
    ({"tls": {"1.3": False}}, "TLS_1_3_NOT_SUPPORTED"),
    ({"tls": {"1.2": False, "1.3": False}}, "NO_MODERN_TLS"),
    ({"ciphers": {"weak": ["TLS_RSA_WITH_RC4_128_SHA"]}}, "WEAK_CIPHERS"),
    ({"ciphers": {"forward_secrecy": False}}, "NO_FORWARD_SECRECY"),
    ({"vulns": {"heartbleed": True}}, "HEARTBLEED"),
    ({"redirect": {"redirects_to_https": False, "status": 200}}, "NO_HTTPS_REDIRECT"),
])
def test_each_problem_creates_its_finding(changes, expected_id):
    assert expected_id in findings_for(**changes)


def test_header_and_cookie_findings():
    headers = {"headers": {**GOOD_HEADERS["headers"], "csp": False},
               "details": {"csp_report_only": True, "hsts_max_age": 31536000},
               "cookies": [{"name": "sid", "secure": False, "httponly": True, "samesite": "Lax"}]}
    ids = findings_for(headers=headers)
    assert "CSP_REPORT_ONLY" in ids and "CSP_MISSING" not in ids
    assert "COOKIE_NOT_SECURE" in ids and "COOKIE_NO_HTTPONLY" not in ids


@pytest.mark.parametrize("finding_id, severity, expected", [
    ("CERT_EXPIRED", "critical", (59, "F")),   # 70 points, but capped at 59
    ("WEAK_CIPHERS", "high", (79, "C")),       # 85 points, but capped at 79
    ("TLS_1_0_ENABLED", "high", (85, "B")),    # cap 89 is above 85, so it does not apply
    ("HSTS_MISSING", "medium", (92, "A")),     # no cap
])
def test_score_caps(finding_id, severity, expected):
    score, grade, _cap = calculate_score([{"id": finding_id, "severity": severity, "evidence": "x"}])
    assert (score, grade) == expected


def test_points_lost_is_recorded_on_each_finding():
    findings = [{"id": "HSTS_MISSING", "severity": "medium", "evidence": "x"},
                {"id": "REFERRER_POLICY_MISSING", "severity": "low", "evidence": "x"}]
    calculate_score(findings)
    assert [f["points_lost"] for f in findings] == [8, 3]


def test_every_possible_finding_has_an_explanation():
    import inspect
    import re
    import scanner.score
    source = inspect.getsource(scanner.score)
    ids = set(re.findall(r'"([A-Z][A-Z0-9_]{3,})", "(?:critical|high|medium|low)"', source))
    assert len(ids) >= 30
    assert ids <= set(EXPLANATIONS), ids - set(EXPLANATIONS)
    assert explain_findings([{"id": "NOT_A_REAL_ID"}]) == {}  # unknown ids are never explained


def test_header_parsing():
    assert _parse_hsts("max-age=31536000; includeSubDomains; preload") == (31536000, True, True)
    assert _parse_hsts("max-age=0") == (0, False, False)
    assert _csp_weaknesses("script-src 'self' 'unsafe-inline'") == ["unsafe-inline"]
    assert _csp_weaknesses("script-src 'nonce-abc' 'unsafe-inline'") == []  # ignored by browsers with a nonce
    assert _csp_weaknesses("script-src 'unsafe-eval'") == ["unsafe-eval"]
    assert _csp_weaknesses("script-src 'self'; style-src 'self' 'unsafe-inline'") == []  # styles only: not reported
    assert _csp_weaknesses("default-src 'self' 'unsafe-inline'") == ["unsafe-inline"]   # default-src covers scripts
    assert _parse_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax") == \
        {"name": "sid", "secure": True, "httponly": True, "samesite": "Lax"}
    assert _parse_cookie("pref=1") == {"name": "pref", "secure": False, "httponly": False, "samesite": None}


def test_dns_and_variant_names():
    assert _candidates("www.shop.example.com") == ["www.shop.example.com", "shop.example.com", "example.com"]
    assert other_name("www.example.com") == "example.com"
    assert other_name("example.com") == "www.example.com"


def test_scanner_refuses_internal_addresses():
    with pytest.raises(ValueError):
        resolve_public("localhost")


def test_one_weakness_cannot_wipe_out_the_score():
    """Real www.google.com findings: 12 problems used to add up to 104 points (score 0)."""
    ids = [("TLS_1_0_ENABLED", "high"), ("TLS_1_1_ENABLED", "high"), ("WEAK_CIPHERS", "high"),
           ("NO_HTTPS_REDIRECT", "high"), ("HSTS_MISSING", "medium"), ("CSP_REPORT_ONLY", "medium"),
           ("COOKIE_NOT_SECURE", "medium"), ("VARIANT_NO_HTTPS_REDIRECT", "medium"),
           ("X_CONTENT_TYPE_OPTIONS_MISSING", "low"), ("REFERRER_POLICY_MISSING", "low"),
           ("COOKIE_NO_HTTPONLY", "low"), ("COOKIE_NO_SAMESITE", "low")]
    findings = [{"id": i, "severity": s, "evidence": "x"} for i, s in ids]
    score, grade, _cap = calculate_score(findings)
    by_category = {}
    for f in findings:
        by_category[f["category"]] = by_category.get(f["category"], 0) + f["points_lost"]
    assert by_category == {"protocols": 25, "enforcement": 20, "headers": 14, "cookies": 10}
    assert score == 100 - 69 == 31 and grade == "F"
    assert sum(f["points_lost"] for f in findings) == 100 - score  # the list adds up to the score


def test_most_serious_finding_is_charged_first_within_a_category():
    findings = [{"id": "COOKIE_NO_SAMESITE", "severity": "low", "evidence": "x"},
                {"id": "COOKIE_NOT_SECURE", "severity": "medium", "evidence": "x"},
                {"id": "COOKIE_NO_HTTPONLY", "severity": "low", "evidence": "x"}]
    calculate_score(findings)
    # Medium first (8), then the low ones in scan order until the limit of 10 is reached.
    assert [f["points_lost"] for f in findings] == [2, 8, 0]


@pytest.mark.parametrize("host, expected", [
    ("example.com", True), ("www.example.com", True), ("example.co.in", True), ("www.example.co.in", True),
    ("api.github.com", False),                # a subdomain has no www twin people type
    ("securesphere-psi.vercel.app", False),   # shared hosting: *.vercel.app can never cover www.<name>
    ("www.securesphere-psi.vercel.app", False),
    ("kshitij0303.github.io", False),
])
def test_www_check_only_for_main_domains(host, expected):
    from scanner.variant import applies_to
    assert applies_to(host) is expected


def test_firewall_challenge_page_is_could_not_check_not_missing(monkeypatch):
    """A bot-protection page has none of the site's headers; that must be "could not check", not "missing"."""
    import email.message
    import scanner.headers as h
    challenge = email.message.Message()
    challenge["X-Vercel-Mitigated"] = "challenge"
    monkeypatch.setattr(h, "_fetch_home_page", lambda host, ip: (challenge, "https://x.vercel.app/"))
    result = h.check_headers("x.vercel.app")
    assert set(result["headers"].values()) == {None}
    assert result["details"] == {"blocked_by": "Vercel bot protection"}
    ids = findings_for(headers=result)
    assert not any(i.startswith(("HSTS", "CSP", "X_", "REFERRER", "COOKIE")) for i in ids)
