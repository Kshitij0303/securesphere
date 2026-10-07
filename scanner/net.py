"""Network helpers shared by all checks.

Every check connects to an IP address that was resolved and checked ONCE, while still using the domain
name for TLS (SNI) and the HTTP Host header. Looking the name up again for each connection would let a
malicious domain answer with a public IP for the safety check and an internal one for the scan
(DNS rebinding)."""
import http.client
import ipaddress
import socket
import ssl


def resolve_public(host: str) -> str:
    """Returns one public IP for host (IPv4 preferred). Raises ValueError if it does not resolve or if
    any address is private/internal (localhost, 10.x, 192.168.x, ...)."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"{host} could not be resolved")
    addresses = [info[4][0] for info in infos]
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError(f"{host} points to a private or internal address")
    ipv4 = [a for a in addresses if ipaddress.ip_address(a).version == 4]
    return (ipv4 or addresses)[0]


def connect(host: str, port: int, ip: str | None, timeout: float) -> socket.socket:
    """TCP connection to the pinned IP (or the name, when no IP was given)."""
    return socket.create_connection((ip or host, port), timeout=timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a fixed IP, with SNI and certificate name set to the real host."""

    def __init__(self, host: str, ip: str | None, context: ssl.SSLContext, timeout: float):
        super().__init__(host, 443, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = connect(self.host, self.port, self._ip, self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP to a fixed IP, with the Host header set to the real host."""

    def __init__(self, host: str, ip: str | None, timeout: float):
        super().__init__(host, 80, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = connect(self.host, self.port, self._ip, self.timeout)
