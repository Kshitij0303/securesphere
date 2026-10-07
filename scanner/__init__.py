"""SecureSphere scanner (Part 1). The backend only uses these two functions:
  run_scan(domain, ip=None, progress=None)
      -> certificate, tls, ciphers, headers, header_details, cookies, redirect, vulnerabilities,
         dns, variant, findings, score, grade, score_cap
  explain_findings(list)  -> {finding id: {title, problem, why_it_matters, impact, fix}}

All checks run at the same time in worker threads. The certificate check decides whether the site is
reachable at all; every other check that fails is reported as None ("could not test") instead of
failing the whole scan. TLS versions and weak ciphers come from sslyze when it is installed (it can
test old protocols and ciphers), otherwise from the built-in Python checks.

Every connection goes to one IP address that is checked to be public before the scan starts (pass the
IP the caller already checked, or the scanner looks it up itself). progress(step) is called from worker
threads as each check finishes, so a UI can show how far the scan is."""
import logging
import threading
import time
from typing import Callable

from scanner.cert import check_certificate
from scanner.ciphers import WEAK_FAMILIES, check_ciphers
from scanner.deep_tls import deep_scan
from scanner.dns_checks import check_dns
from scanner.explain import explain_findings
from scanner.headers import HEADERS, check_headers
from scanner.net import resolve_public_all
from scanner.redirect import check_https_redirect
from scanner.score import build_findings, calculate_score
from scanner.tls_check import VERSIONS, check_tls_versions
from scanner.variant import applies_to, check_variant, other_name

__all__ = ["run_scan", "explain_findings", "STEPS"]

log = logging.getLogger("securesphere.scanner")
SCAN_BUDGET = 50  # seconds for the whole scan; slower checks become "could not test" (backend limit is 60)
# Step names reported to progress(), in the order a UI may list them.
STEPS = ("certificate", "protocols", "ciphers", "deep", "headers", "redirect", "dns", "variant")


def _start(step: str, progress, fn, *args) -> tuple[threading.Thread, dict]:
    """Runs a check in a daemon thread, so a stuck check can never keep the program from exiting."""
    box: dict = {}

    def run():
        try:
            box["value"] = fn(*args)
        except BaseException as e:
            box["error"] = e
        if progress:
            try:
                progress(step)
            except Exception:
                pass

    thread = threading.Thread(target=run, daemon=True, name=f"scan-{step}")
    thread.start()
    return thread, box


def _wait(job, deadline: float, default, required: bool = False):
    """Waits until the shared deadline. Optional checks that fail or run late return the default."""
    thread, box = job
    thread.join(max(0.0, deadline - time.monotonic()))
    if thread.is_alive():
        if required:
            raise TimeoutError("The site took too long to answer")
        log.warning("%s did not finish in time", thread.name)
        return default
    if "error" in box:
        if required:
            raise box["error"]
        log.warning("%s failed: %r", thread.name, box["error"])
        return default
    return default if box.get("value") is None else box["value"]


def run_scan(domain: str, port: int = 443, ip: str | list[str] | None = None,
             progress: Callable[[str], None] | None = None) -> dict:
    ip = ip or resolve_public_all(domain)  # raises ValueError for private/internal addresses
    deadline = time.monotonic() + SCAN_BUDGET
    cert_job = _start("certificate", progress, check_certificate, domain, port, ip)
    deep_job = _start("deep", progress, deep_scan, domain, port, ip)
    tls_job = _start("protocols", progress, check_tls_versions, domain, port, ip)
    cipher_job = _start("ciphers", progress, check_ciphers, domain, port, ip)
    header_job = _start("headers", progress, check_headers, domain, ip)
    redirect_job = _start("redirect", progress, check_https_redirect, domain, ip)
    dns_job = _start("dns", progress, check_dns, domain)
    # The www check only makes sense for a main domain; for others the step is reported done straight away.
    variant_job = _start("variant", progress, check_variant, domain) if applies_to(domain) else None
    if variant_job is None and progress:
        progress("variant")

    cert = _wait(cert_job, deadline, None, required=True)  # raises if the site cannot be reached over HTTPS
    native_tls = _wait(tls_job, deadline, dict.fromkeys(VERSIONS))
    ciphers = _wait(cipher_job, deadline, {"negotiated": None, "protocol": None, "accepted": [], "weak": [],
                                           "forward_secrecy": None, "untested": list(WEAK_FAMILIES)})
    headers = _wait(header_job, deadline, {"headers": dict.fromkeys(HEADERS), "details": {}, "cookies": []})
    redirect = _wait(redirect_job, deadline, {"http_open": None, "redirects_to_https": None, "status": None, "location": None})
    dns = _wait(dns_job, deadline, {"caa": None, "dnssec": None, "hsts_preloaded": None})
    variant = _wait(variant_job, deadline, {"host": other_name(domain), "exists": None}) if variant_job else None
    deep = _wait(deep_job, deadline, None)

    native = {"1.0": native_tls["tls1_0"], "1.1": native_tls["tls1_1"], "1.2": native_tls["tls1_2"], "1.3": native_tls["tls1_3"]}
    if cert.get("fetched_with") == "sslyze":
        # This computer's OpenSSL could not talk to the server at all (e.g. RC4 only), so its "refused"
        # answers mean nothing: only sslyze's results count.
        native = {k: (None if v is False else v) for k, v in native.items()}
    if deep:
        # sslyze is more complete; the built-in check fills any version sslyze could not test.
        tls = {k: (deep["versions"].get(k) if deep["versions"].get(k) is not None else native.get(k))
               for k in ("ssl2", "ssl3", "1.0", "1.1", "1.2", "1.3")}
        ciphers.update(accepted=deep["accepted"] or ciphers["accepted"], weak=deep["weak"], untested=[], engine="sslyze")
        vulns = deep["vulnerabilities"]
    else:
        tls = {"ssl2": None, "ssl3": None, **native}
        ciphers["engine"] = "python-ssl"
        vulns = {"heartbleed": None, "ccs_injection": None, "robot": None}

    # Checks that could not run at all: the score then only counts the checks that did, and the UI must say so.
    untested = []
    if all(v is None for v in tls.values()):
        untested.append("TLS versions")
    redirects_to = headers["details"].get("redirects_to")
    if redirects_to:
        untested.append(f"Page headers (this site sends visitors to {redirects_to}: scan that address)")
    elif headers["details"].get("https_no_page"):
        untested.append("Security headers and cookies (the site serves no page over HTTPS)")
    elif all(v is None for v in headers["headers"].values()):
        blocked = headers["details"].get("blocked_by")
        untested.append(f"Security headers and cookies (blocked by {blocked})" if blocked else "Security headers and cookies")
    if redirect.get("http_open") is None:
        untested.append("HTTP to HTTPS redirect")
    elif redirect.get("blocked"):
        untested.append(f"HTTP to HTTPS redirect (blocked by the site's firewall, HTTP {redirect['status']})")
    if not deep:
        untested.append("Full cipher and vulnerability tests")
    if all(v is None for v in dns.values()):
        untested.append("DNS checks")

    findings = build_findings(cert, tls, ciphers, headers, redirect, vulns, dns, variant)
    score, grade, cap = calculate_score(findings, untested)
    return {
        "certificate": cert,
        "tls": tls,  # True / False / None (could not test)
        "ciphers": ciphers,
        "headers": headers["headers"],
        "header_details": headers["details"],
        "cookies": headers["cookies"],
        "redirect": redirect,
        "vulnerabilities": vulns,
        "dns": dns,
        "variant": variant,
        "findings": findings,
        "score": score,
        "grade": grade,
        "score_cap": cap,
        "untested": untested,  # names of checks that could not run; empty = a complete result
    }
