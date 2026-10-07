"""Cipher check: which cipher the server picks by default, and whether it still accepts known-weak ones.

Weak ciphers are tested by offering ONLY that family. If this computer's OpenSSL no longer contains a
family at all, it cannot be tested and is listed under "untested" instead of being called safe."""
import ssl

from scanner.net import connect

TIMEOUT = 6

WEAK_FAMILIES = {
    "RC4": "RC4",
    "3DES": "3DES",
    "DES": "DES",
    "NULL (no encryption)": "eNULL",
    "Anonymous (no authentication)": "aNULL",
    "EXPORT": "EXP",
}


def _loose_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _connect(host: str, port: int, ctx: ssl.SSLContext, ip: str | None = None) -> tuple[str, str]:
    with connect(host, port, ip, TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            name, protocol, _bits = tls.cipher()
            return name, protocol


def check_ciphers(host: str, port: int = 443, ip: str | None = None) -> dict:
    try:
        negotiated, protocol = _connect(host, port, _loose_context(), ip)
    except (ssl.SSLError, ConnectionResetError):  # some old servers just drop modern handshakes
        # The server refused every modern cipher; offer everything to see what it does pick.
        ctx = _loose_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        try:
            negotiated, protocol = _connect(host, port, ctx, ip)
        except (ssl.SSLError, OSError):
            # Only ciphers this computer's OpenSSL no longer has: report "could not test", not "safe".
            return {"negotiated": None, "protocol": None, "accepted": [], "weak": [],
                    "forward_secrecy": None, "untested": list(WEAK_FAMILIES)}

    weak, untested = [], []
    for label, spec in WEAK_FAMILIES.items():
        ctx = _loose_context()
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # TLS 1.3 has no weak ciphers to offer
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers(f"{spec}:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            untested.append(label)
            continue
        try:
            name, _ = _connect(host, port, ctx, ip)
            weak.append(name)
        except (ssl.SSLError, OSError):
            pass  # refused: good

    return {
        "negotiated": negotiated,
        "protocol": protocol,
        "accepted": [negotiated] + [w for w in weak if w != negotiated],
        "weak": weak,
        # TLS 1.3 always has forward secrecy; before that it needs (EC)DHE key exchange.
        "forward_secrecy": protocol == "TLSv1.3" or "DHE" in negotiated,
        "untested": untested,
    }
