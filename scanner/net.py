"""Network helpers shared by all checks.

Every check connects to an IP address that was resolved and checked ONCE, while still using the domain
name for TLS (SNI) and the HTTP Host header. Looking the name up again for each connection would let a
malicious domain answer with a public IP for the safety check and an internal one for the scan
(DNS rebinding)."""
import http.client
import ipaddress
import socket
import ssl


# How the scanner introduces itself. The "Mozilla/5.0 (compatible; ...)" form is the standard one for honest
# bots (search engines, Mozilla Observatory): many firewalls block other formats outright. It still names
# SecureSphere and links to it, so site owners can see who visited.
USER_AGENT = "Mozilla/5.0 (compatible; SecureSphere/1.0; +https://securesphere-psi.vercel.app)"
REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def resolve_public_all(host: str) -> list[str]:
    """Every address of host, IPv4 first. Raises ValueError if it does not resolve or if ANY address is
    private/internal (localhost, 10.x, 192.168.x, ...): one bad address is enough to refuse the scan."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"{host} could not be resolved")
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError(f"{host} points to a private or internal address")
    return sorted(addresses, key=lambda a: ipaddress.ip_address(a).version)


def resolve_public(host: str) -> str:
    """One checked public address of host (see resolve_public_all)."""
    return resolve_public_all(host)[0]


def connect(host: str, port: int, ip: str | list[str] | None, timeout: float) -> socket.socket:
    """TCP connection to the checked address(es), trying each in turn like a browser does (a site's IPv4
    address may be down while its IPv6 one works). With no address given, connects by name."""
    if not ip:
        return socket.create_connection((host, port), timeout=timeout)
    last_error: OSError | None = None
    for address in [ip] if isinstance(ip, str) else ip:
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as e:
            last_error = e
    raise last_error


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
