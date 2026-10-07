"""Certificate check: who issued it, when it expires and whether a browser would trust it.

The trick: a broken certificate (expired, wrong domain, self-signed) makes the strict connection fail.
So we connect twice: first strictly, like a browser, to learn whether it is trusted. If that fails we
save the reason, connect again without checking, and still read the certificate details."""
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from scanner.net import connect

TIMEOUT = 8
WEAK_HASHES = ("md5", "sha1")


def _fetch_der(host: str, port: int, context: ssl.SSLContext, ip: str | None = None) -> bytes:
    with connect(host, port, ip, TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def _reason(err: ssl.SSLCertVerificationError) -> str:
    msg = (err.verify_message or str(err)).lower()
    # Order matters: the untrusted-root message also contains "self signed".
    if "in certificate chain" in msg:
        return "untrusted_root"
    if "self-signed" in msg or "self signed" in msg:
        return "self_signed"
    if "expired" in msg:
        return "expired"
    if "hostname mismatch" in msg or "not valid for" in msg or "doesn't match" in msg:
        return "hostname_mismatch"
    if "local issuer" in msg or "unable to get issuer" in msg:
        return "untrusted_issuer"
    return "untrusted"


def _name(name: x509.Name) -> str | None:
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return None


def _dns_names(cert: x509.Certificate) -> list[str]:
    """The domain names a certificate covers: the SAN list, or the old Common Name if there is none."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
        if names:
            return names
    except x509.ExtensionNotFound:
        pass
    return [str(a.value) for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]


def hostname_matches(host: str, names: list[str]) -> bool:
    """Browser rules: exact match, or "*.example.com" covering exactly one extra label
    (a.example.com yes; example.com and a.b.example.com no)."""
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") == name.count(".") and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def _key_info(cert: x509.Certificate) -> tuple[str, int | None, bool]:
    """(key type, key size in bits, is it too weak). RSA/DSA need 2048+ bits, elliptic curves 224+."""
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, key.key_size < 2048
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, key.key_size < 2048
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size, key.curve.key_size < 224
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, False
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456, False
    return "Unknown", None, False


def check_certificate(host: str, port: int = 443, ip: str | None = None) -> dict:
    """Connection errors (site down, no HTTPS) are raised to the caller on purpose."""
    result = {"trusted": False, "error": None, "domain_match": None, "self_signed": False,
              "issuer": None, "subject": None, "names": [], "expires_at": None, "days_left": None, "expired": None,
              "key_type": None, "key_size": None, "weak_key": None, "signature_hash": None, "weak_signature": None}

    try:
        der = _fetch_der(host, port, ssl.create_default_context(), ip)
        result["trusted"] = True
    except ssl.SSLCertVerificationError as e:
        reason = _reason(e)
        result["error"] = reason
        result["self_signed"] = reason == "self_signed"
        loose = ssl.create_default_context()
        loose.check_hostname = False
        loose.verify_mode = ssl.CERT_NONE
        der = _fetch_der(host, port, loose, ip)

    cert = x509.load_der_x509_certificate(der)
    names = _dns_names(cert)
    # A trusted certificate already passed the hostname check. For broken ones we check the names by hand,
    # so expired or self-signed certificates still get a real yes/no instead of "unknown".
    result["domain_match"] = True if result["trusted"] else hostname_matches(host, names)
    result["names"] = names[:20]

    expires = cert.not_valid_after_utc  # needs cryptography >= 42
    result["issuer"] = _name(cert.issuer)
    result["subject"] = _name(cert.subject)
    result["expires_at"] = expires.date().isoformat()
    result["days_left"] = (expires - datetime.now(timezone.utc)).days
    result["expired"] = expires < datetime.now(timezone.utc)

    result["key_type"], result["key_size"], result["weak_key"] = _key_info(cert)
    hash_alg = cert.signature_hash_algorithm  # None for Ed25519/Ed448, which are strong
    result["signature_hash"] = hash_alg.name if hash_alg else result["key_type"]
    result["weak_signature"] = bool(hash_alg and hash_alg.name in WEAK_HASHES)
    return result
