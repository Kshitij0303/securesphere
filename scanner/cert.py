"""Certificate check: who issued it, when it expires and whether a browser would trust it.

The trick: a broken certificate (expired, wrong domain, self-signed) makes the strict connection fail.
So we connect twice: first strictly, like a browser, to learn whether it is trusted. If that fails we
save the reason, connect again without checking, and still read the certificate details.

Two more cases browsers handle that a plain strict connection does not:
- Old servers that only speak TLS 1.0 or old ciphers: we retry with a "legacy" connection, and for ciphers
  this computer's OpenSSL no longer has (RC4), we let sslyze (its own older OpenSSL) fetch the certificate.
- An incomplete chain (the server forgets to send the intermediate certificate): Chrome, Edge and Safari
  download it from the address written in the certificate (AIA); Firefox, apps and older devices fail.
  We do the same download, and report "incomplete chain" instead of "untrusted"."""
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from scanner.deep_tls import fetch_certificate_chain
from scanner.net import PinnedHTTPConnection, REQUEST_HEADERS, connect, resolve_public_all

TIMEOUT = 8
WEAK_HASHES = ("md5", "sha1")
MAX_AIA_BYTES = 64 * 1024


def tls_context(verify: bool, legacy: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if legacy:  # offer TLS 1.0+ and every cipher this OpenSSL still has
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


def fetch_chain(host: str, port: int, ctx: ssl.SSLContext, ip: str | None) -> list[bytes]:
    """The certificates the server sends, leaf first, as DER bytes."""
    with connect(host, port, ip, TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            chain = tls.get_unverified_chain() if hasattr(tls, "get_unverified_chain") else None
            return list(chain) if chain else [tls.getpeercert(binary_form=True)]


def failure_reason(err: ssl.SSLCertVerificationError) -> str:
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
    if "local issuer" in msg or "unable to get issuer" in msg or "unable to verify the first certificate" in msg:
        return "untrusted_issuer"  # may only be a missing intermediate: see _diagnose_missing_issuer
    return "untrusted"


def _download_issuer(leaf: x509.Certificate) -> bytes | None:
    """The issuer certificate from the leaf's AIA "CA Issuers" address (http only, public address only)."""
    try:
        aia = leaf.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    for desc in aia:
        if desc.access_method != AuthorityInformationAccessOID.CA_ISSUERS:
            continue
        url = urlsplit(desc.access_location.value)
        if url.scheme != "http" or not url.hostname:
            continue
        try:
            conn = PinnedHTTPConnection(url.hostname, resolve_public_all(url.hostname), TIMEOUT)
            conn.request("GET", url.path or "/", headers=REQUEST_HEADERS)
            resp = conn.getresponse()
            data = resp.read(MAX_AIA_BYTES) if resp.status == 200 else b""
            conn.close()
        except (OSError, ValueError):
            continue
        for load in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
            try:
                return load(data).public_bytes(Encoding.DER)
            except ValueError:
                pass
        for load_bundle in (pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):  # .p7c files
            try:
                bundle = load_bundle(data)
                if bundle:
                    return bundle[0].public_bytes(Encoding.DER)
            except ValueError:
                pass
    return None


def diagnose_missing_issuer(host: str, port: int, ip: str | None, leaf_der: bytes, legacy: bool = False) -> str:
    """After an "unable to get issuer" failure: download the missing intermediate like Chrome does and try again.
    Returns "chain_incomplete" when that fixes it, otherwise the real reason (e.g. "expired")."""
    issuer = _download_issuer(x509.load_der_x509_certificate(leaf_der))
    if not issuer:
        return "untrusted_issuer"
    ctx = tls_context(verify=True, legacy=legacy)
    ctx.load_verify_locations(cadata=issuer)
    try:
        fetch_chain(host, port, ctx, ip)
        return "chain_incomplete"
    except ssl.SSLCertVerificationError as e:
        return failure_reason(e)
    except (ssl.SSLError, OSError):
        return "untrusted_issuer"


def _attempt(host: str, port: int, ip: str | None, legacy: bool) -> tuple[list[bytes], str | None]:
    """(chain, None) when trusted; (chain, reason) when the certificate is broken. Other TLS errors are raised."""
    try:
        return fetch_chain(host, port, tls_context(True, legacy), ip), None
    except ssl.SSLCertVerificationError as e:
        reason = failure_reason(e)
        chain = fetch_chain(host, port, tls_context(False, legacy), ip)
        if reason == "untrusted_issuer":
            reason = diagnose_missing_issuer(host, port, ip, chain[0], legacy)
        return chain, reason


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


def check_certificate(host: str, port: int = 443, ip: str | list[str] | None = None) -> dict:
    """Connection errors (site down, no HTTPS) are raised to the caller on purpose."""
    result = {"trusted": False, "error": None, "domain_match": None, "self_signed": False, "legacy_only": False,
              "issuer": None, "subject": None, "names": [], "expires_at": None, "days_left": None, "expired": None,
              "key_type": None, "key_size": None, "weak_key": None, "signature_hash": None, "weak_signature": None,
              "weak_signature_in": [], "chain_length": None}

    result["fetched_with"] = "python"
    try:
        try:
            chain, reason = _attempt(host, port, ip, legacy=False)
        except (TimeoutError, ConnectionResetError):  # a slow or dropped handshake is retried once
            chain, reason = _attempt(host, port, ip, legacy=False)
    except ssl.SSLError as first_error:
        # The handshake itself failed: maybe the server only speaks TLS 1.0 or old ciphers.
        result["legacy_only"] = True
        try:
            chain, reason = _attempt(host, port, ip, legacy=True)
        except ssl.SSLError:
            found = fetch_certificate_chain(host, port, ip)  # sslyze's own OpenSSL still has RC4 and friends
            if not found:
                raise first_error
            chain, trusted = found
            reason = None if trusted else "untrusted"
            result["fetched_with"] = "sslyze"

    certs = [x509.load_der_x509_certificate(der) for der in chain]
    leaf = certs[0]
    names = _dns_names(leaf)
    expires = leaf.not_valid_after_utc  # needs cryptography >= 42
    now = datetime.now(timezone.utc)
    if reason == "untrusted" and leaf.issuer == leaf.subject:
        reason = "self_signed"  # sslyze path: name the reason when we can
    if reason is None and not hostname_matches(host, names):
        reason = "hostname_mismatch"  # sslyze checks the chain, not the name

    # A chain that only lacked an intermediate is trusted by Chrome, Edge and Safari.
    result["trusted"] = reason in (None, "chain_incomplete")
    result["error"] = reason
    result["self_signed"] = reason == "self_signed"
    # Broken certificates still get a real yes/no for the name, checked by hand.
    result["domain_match"] = True if result["trusted"] else hostname_matches(host, names)
    result["names"] = names[:20]
    result["issuer"] = _name(leaf.issuer)
    result["subject"] = _name(leaf.subject)
    result["expires_at"] = expires.date().isoformat()
    result["days_left"] = (expires - now).days
    result["expired"] = expires < now
    result["key_type"], result["key_size"], result["weak_key"] = _key_info(leaf)
    hash_alg = leaf.signature_hash_algorithm  # None for Ed25519/Ed448, which are strong
    result["signature_hash"] = hash_alg.name if hash_alg else result["key_type"]
    result["chain_length"] = len(certs)

    # SHA-1/MD5 anywhere in the chain the server sends (a root's signature on itself is never checked).
    for position, cert in enumerate(certs):
        if position > 0 and cert.issuer == cert.subject:
            continue
        alg = cert.signature_hash_algorithm
        if alg and alg.name in WEAK_HASHES:
            result["weak_signature_in"].append("certificate" if position == 0 else "intermediate certificate")
    result["weak_signature"] = bool(result["weak_signature_in"])
    return result
