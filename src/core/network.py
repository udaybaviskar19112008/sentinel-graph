"""IP address helpers shared by route forensics and sandbox egress control."""

import ipaddress

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_ip(text: str) -> IPAddress | None:
    """Parse an IPv4/IPv6 literal; IPv4-mapped IPv6 (``::ffff:10.0.0.1``) collapses to IPv4."""
    try:
        ip = ipaddress.ip_address(text.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_bogon(ip: IPAddress) -> bool:
    """Not publicly routable: RFC 1918, loopback, link-local, CGNAT, ULA, documentation, reserved.

    ``is_global`` covers all of those but counts multicast as global, so that is added back.
    """
    return not ip.is_global or ip.is_multicast
