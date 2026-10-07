"""Module 5: Domain safety. Users type domains, so we clean them and block internal targets."""
import ipaddress
import re
import socket

from fastapi import HTTPException

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def clean_domain(raw: str) -> str:
    """'https://Example.com/path' -> 'example.com'. Rejects anything that is not a hostname."""
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split("?")[0].split(":")[0]
    if not HOST_RE.match(d):
        raise HTTPException(400, "Enter a valid public domain, for example example.com")
    return d


def assert_public(domain: str) -> str:
    """Blocking call (DNS lookup). Rejects localhost, 10.x, 192.168.x, 172.16-31.x and similar.

    Returns the checked IP address. The scanner connects to exactly this address, so a domain cannot
    answer with a public IP here and a private one a moment later (DNS rebinding)."""
    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise HTTPException(400, "This domain could not be resolved")
    addresses = [info[4][0] for info in infos]
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise HTTPException(400, "Private or internal addresses cannot be scanned")
    ipv4 = [a for a in addresses if ipaddress.ip_address(a).version == 4]
    return (ipv4 or addresses)[0]
