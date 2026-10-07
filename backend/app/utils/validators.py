"""Module 5: Domain safety. Users type domains, so we clean them and block internal targets."""
import ipaddress
import re
import socket

import dns.exception
import dns.resolver

from fastapi import HTTPException

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def clean_domain(raw: str) -> str:
    """'https://Example.com/path' -> 'example.com'. Rejects anything that is not a hostname."""
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d, _, port = d.partition(":")
    if port and port != "443":
        # The scan pipeline, history and monitoring all work on the standard HTTPS port only.
        raise HTTPException(400, f"SecureSphere checks websites on the standard HTTPS port (443). "
                                 f"Remove :{port} and try again.")
    if not HOST_RE.match(d):
        raise HTTPException(400, "That doesn't look like a website address. Try something like example.com")
    return d


def assert_public(domain: str) -> list[str]:
    """Blocking call (DNS lookup). Rejects localhost, 10.x, 192.168.x, 172.16-31.x and similar.

    Returns the checked IP addresses. The scanner connects only to these addresses, so a domain cannot
    answer with a public IP here and a private one a moment later (DNS rebinding)."""
    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise HTTPException(400, f"{domain} doesn't exist. Check the spelling and try again.")
    addresses = [info[4][0] for info in infos]
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise HTTPException(400, f"{domain} points to a private network, so it can't be scanned.")
    # Every checked address, IPv4 first: the scanner tries them in turn and never uses an unchecked one.
    return sorted(dict.fromkeys(addresses), key=lambda a: ipaddress.ip_address(a).version)


def resolve_target(domain: str) -> tuple[str, list[str]]:
    """(domain to scan, its checked IP addresses). Many sites only exist under www (incometax.gov.in has no address,
    www.incometax.gov.in does), so a bare name that does not resolve falls back to its www name."""
    try:
        return domain, assert_public(domain)
    except HTTPException as error:
        if domain.startswith("www.") or "doesn't exist" not in str(error.detail):
            raise
        try:
            return f"www.{domain}", assert_public(f"www.{domain}")
        except HTTPException:
            raise error  # report the name the user typed


def email_domain_accepts_mail(email: str) -> bool:
    """Blocking call (DNS). False only when DNS clearly says the address's domain cannot receive email:
    it does not exist, has a "null MX" (RFC 7505: accepts no mail), or has neither MX nor address records.
    A DNS problem on our side returns True, so a real person is never turned away by a timeout."""
    domain = email.rsplit("@", 1)[-1].strip().lower()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    try:
        hosts = [str(r.exchange).rstrip(".") for r in resolver.resolve(domain, "MX")]
        return any(hosts)  # a null MX is the single host "." -> ""
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        try:  # no MX: mail is delivered to the domain's own address, if it has one
            resolver.resolve(domain, "A")
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except dns.exception.DNSException:
            return True
    except dns.exception.DNSException:
        return True
