"""TLS version check: connect once per version, allowing only that version.
If the connection works, the server supports it.

Each result is True (supported), False (refused) or None (could not test: this computer's
Python/OpenSSL cannot offer that version). None must never be shown as "not supported"."""
import socket
import ssl

from scanner.net import connect

TIMEOUT = 6

VERSIONS = {
    "tls1_0": (ssl.TLSVersion.TLSv1, "TLSv1"),
    "tls1_1": (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
    "tls1_2": (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
    "tls1_3": (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
}

# OpenSSL errors that mean *we* could not offer the version, not that the server refused it.
LOCAL_LIMITS = ("no protocols available", "no ciphers available", "no_protocols_available", "no_ciphers_available")


def _try_version(host: str, port: int, version: ssl.TLSVersion, expected: str, ip: str | None = None) -> bool | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        # Offer every cipher so we test the version only, not the cipher list (cipher.py judges ciphers).
        # Modern OpenSSL also hides TLS 1.0/1.1 behind security level 0. TLS 1.3 ignores this setting.
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        with connect(host, port, ip, TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.version() == expected
    except ssl.SSLError as e:
        if any(s in str(e).lower() for s in LOCAL_LIMITS):
            return None
        return False
    except (ConnectionResetError, ConnectionAbortedError, socket.timeout, TimeoutError):
        return False  # many servers just drop connections that use an old version


def check_tls_versions(host: str, port: int = 443, ip: str | None = None) -> dict:
    return {key: _try_version(host, port, v, name, ip) for key, (v, name) in VERSIONS.items()}
