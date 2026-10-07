"""www / bare-domain check. Visitors type both example.com and www.example.com, so both must work
securely. We look at the other name: does it exist, does it have a valid certificate, and does its
http:// address redirect to https://?

Only a site's main domain has a www twin that people actually type. The check is skipped for subdomains
(api.github.com) and for addresses on shared hosting (myapp.vercel.app): there the www name is not used,
and the hosting's wildcard certificate (*.vercel.app) can never cover it, which would be a false alarm.

If the other name does not exist in DNS there is nothing to check (and nothing to report)."""
import ssl

from scanner.net import connect, resolve_public
from scanner.redirect import check_https_redirect

TIMEOUT = 8

# Registries that sell names one level down (example.co.in, example.co.uk): the main domain has 3 labels.
SECOND_LEVEL = {
    "co.in", "net.in", "org.in", "ac.in", "edu.in", "gov.in", "res.in", "gen.in", "firm.in", "ind.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au", "co.nz",
    "co.jp", "co.za", "com.br", "com.sg", "com.my", "com.cn", "com.hk", "com.tr", "com.mx", "co.id",
}
# Shared hosting: every customer gets a name under these, covered by the platform's wildcard certificate.
SHARED_HOSTING = (
    "vercel.app", "netlify.app", "github.io", "pages.dev", "workers.dev", "onrender.com", "herokuapp.com",
    "web.app", "firebaseapp.com", "appspot.com", "azurewebsites.net", "cloudfront.net", "fly.dev",
    "railway.app", "up.railway.app", "surge.sh", "glitch.me", "repl.co", "replit.app", "blogspot.com",
)


def other_name(host: str) -> str:
    return host[4:] if host.startswith("www.") else f"www.{host}"


def applies_to(host: str) -> bool:
    """True when host is a main domain (example.com, example.co.in) or its www name."""
    base = host.lower().removeprefix("www.")
    if any(base == s or base.endswith("." + s) for s in SHARED_HOSTING):
        return False
    labels = base.split(".")
    main_domain_labels = 3 if ".".join(labels[-2:]) in SECOND_LEVEL else 2
    return len(labels) == main_domain_labels


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
