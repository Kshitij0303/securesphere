"""www / bare-domain check. Visitors type both example.com and www.example.com, so both must work
securely. We look at the other name: does it exist, does it have a valid certificate, and does its
http:// address redirect to https://?

If the other name does not exist in DNS there is nothing to check (and nothing to report)."""
import ssl

from scanner.net import connect, resolve_public
from scanner.redirect import check_https_redirect

TIMEOUT = 8


def other_name(host: str) -> str:
    return host[4:] if host.startswith("www.") else f"www.{host}"


def check_variant(host: str) -> dict:
    other = other_name(host)
    try:
        ip = resolve_public(other)
    except ValueError:
        return {"host": other, "exists": False}

    result = {"host": other, "exists": True, "https_ok": None, "cert_valid": None, "redirects_to_https": None}
    try:
        with connect(other, 443, ip, TIMEOUT) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=other):
                result["https_ok"], result["cert_valid"] = True, True
    except ssl.SSLCertVerificationError:
        result["https_ok"], result["cert_valid"] = True, False
    except OSError:
        result["https_ok"] = False  # HTTPS is not served on this name at all

    redirect = check_https_redirect(other, ip)
    result["redirects_to_https"] = redirect["redirects_to_https"] if redirect["http_open"] else None
    return result
