"""IP and CIDR to 128-bit integers, so prefix matching is an integer range join.

IPv4 lives in the IPv4-mapped block ::ffff:0:0/96, so one UHUGEINT column holds both families.
"""
from __future__ import annotations

import ipaddress

V4_BASE = 0xFFFF << 32


def ip_int(s: str | None) -> int | None:
    if not s:
        return None
    s = s.strip().split("%", 1)[0]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.version == 4:
        return V4_BASE | int(a)
    m = a.ipv4_mapped
    return V4_BASE | int(m) if m else int(a)


def canonical(s: str | None) -> str | None:
    """RFC 5952 text for an address; IPv4-mapped IPv6 becomes plain IPv4. None if not an address."""
    if not s:
        return None
    try:
        a = ipaddress.ip_address(s.strip().split("%", 1)[0].strip("[]"))
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return str(a)


def net_range(s: str) -> tuple[int, int, str] | None:
    """'203.0.113.0/24' -> (lo, hi, normalised). A bare IP is a /32 or /128."""
    try:
        n = ipaddress.ip_network(s.strip(), strict=False)
    except ValueError:
        return None
    lo, hi = int(n.network_address), int(n.broadcast_address)
    if n.version == 4:
        lo, hi = V4_BASE | lo, V4_BASE | hi
    return lo, hi, str(n)


def is_ip(s: str) -> bool:
    return ip_int(s) is not None


def special(s: str) -> bool:
    """Multicast, limited broadcast, unspecified or loopback: never a device or an indicator hit.

    An address ending in .255 is an ordinary host outside a /24 boundary, so it is not special here;
    a home subnet's own broadcast address is excluded from devices separately (devices.home_table).
    """
    try:
        a = ipaddress.ip_address(s.split("%", 1)[0])
    except ValueError:
        return True
    return a.is_multicast or a.is_unspecified or a.is_loopback or str(a) == "255.255.255.255"


def eui64_mac(s: str) -> str | None:
    """MAC embedded in a modified EUI-64 IPv6 interface id (…ff:fe…), else None."""
    try:
        a = ipaddress.ip_address(s.split("%", 1)[0])
    except ValueError:
        return None
    if a.version != 6 or a.ipv4_mapped:
        return None
    iid = int(a) & ((1 << 64) - 1)
    b = iid.to_bytes(8, "big")
    if b[3] != 0xFF or b[4] != 0xFE:
        return None
    mac = bytes([b[0] ^ 0x02, b[1], b[2], b[5], b[6], b[7]])
    return ":".join(f"{x:02x}" for x in mac)


def prefix_of(s: str) -> str | None:
    """The /24 (IPv4) or /64 (IPv6) containing an address."""
    try:
        a = ipaddress.ip_address(s.split("%", 1)[0])
    except ValueError:
        return None
    plen = 24 if a.version == 4 else 64
    return str(ipaddress.ip_network(f"{a}/{plen}", strict=False))


PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"]
