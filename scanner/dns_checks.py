"""DNS checks (no connection to the website itself):
  CAA         - DNS records that say which certificate authorities may issue certificates for the domain.
  DNSSEC      - whether the domain's DNS answers are signed, so they cannot be forged.
  HSTS preload - whether browsers ship with the domain on their built-in "HTTPS only" list.

Every value is True/False, or None when it could not be checked (DNS timeout, list unreachable)."""
import json
import urllib.request

import dns.exception
import dns.resolver

TIMEOUT = 4
PRELOAD_API = "https://hstspreload.org/api/v2/status?domain="


def _candidates(host: str) -> list[str]:
    """www.shop.example.com -> [www.shop.example.com, shop.example.com, example.com].
    Stops at two labels; for registries like co.uk this is an approximation."""
    labels = host.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT
    return r


def check_caa(host: str) -> dict | None:
    """CAA applies to a name and everything below it, so we climb towards the registered domain."""
    resolver = _resolver()
    for name in _candidates(host):
        try:
            answer = resolver.resolve(name, "CAA")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException:
            return None
        issuers = sorted({r.value.decode(errors="replace") for r in answer if r.tag in (b"issue", b"issuewild")})
        return {"present": True, "found_at": name, "issuers": issuers}
    return {"present": False, "found_at": None, "issuers": []}


def check_dnssec(host: str) -> bool | None:
    """A signed zone has a DS record at its parent. We look for one on the name and its parents."""
    resolver = _resolver()
    for name in _candidates(host):
        try:
            resolver.resolve(name, "DS")
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException:
            return None
    return False


def check_hsts_preload(host: str) -> bool | None:
    """Asks the official preload list (hstspreload.org). A parent domain counts if it covers subdomains."""
    try:
        for name in _candidates(host):
            req = urllib.request.Request(PRELOAD_API + name, headers={"User-Agent": "SecureSphere/1.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                status = json.load(resp)
            if status.get("status") == "preloaded" and (name == host or status.get("include_subdomains")):
                return True
        return False
    except Exception:
        return None


def check_dns(host: str) -> dict:
    return {"caa": check_caa(host), "dnssec": check_dnssec(host), "hsts_preloaded": check_hsts_preload(host)}
