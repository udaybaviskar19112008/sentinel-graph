"""Delivery-route forensics over the Received chain.

Hops are evaluated oldest first. Each Received header is written by the receiving
MTA of that hop, so everything below our boundary is only as trustworthy as the
sender: forged hops are exactly what these checks look for.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from itertools import accumulate, pairwise
from typing import Final, TypedDict

from src.core.logger import get_logger
from src.core.network import IPAddress, is_bogon, parse_ip

logger = get_logger(__name__)

CLOCK_SKEW_TOLERANCE: Final = timedelta(seconds=60)

_MAX_RECEIVED_CHARS: Final = 8 * 1024
_IPV4: Final = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"

_FROM_CLAUSE_RE: Final = re.compile(
    r"""
    ^ \s* from \s+
    (?P<clause> .*? )               # everything up to the 'by' clause, the date, or the end
    (?= \s by \s | ; | $ )
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
# HELO/EHLO names are chosen by the connecting client, so an IP literal there proves nothing.
_HELO_RE: Final = re.compile(
    r"""
      \b helo \s* = \s* [^\s()]+              # exim:  (port=443 helo=[10.0.0.7])
    | \( \s* (?: helo | ehlo ) \s [^()]* \)   # qmail: (HELO 10.0.0.7)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_IP_RE: Final = re.compile(
    rf"""
    (?<! [\w.:-] )                    # not the tail of a hostname label or another address
    (?: ipv6: )?                      # RFC 5321 IPv6 address-literal tag
    (?:
        (?P<v4> {_IPV4} ) (?! [\w.-] )                    # a :port suffix is allowed
      | (?P<v6> [0-9a-f]{{0,4}} (?: : [0-9a-f]{{0,4}} ){{2,7}} (?: : {_IPV4} )? ) (?! [\w.:-] )
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_COMMENT_RE: Final = re.compile(r"\([^()]*\)")


class RoutingFindings(TypedDict):
    """The ``HeaderForensics`` fields owned by route analysis."""

    route_hop_count: int
    private_ip_leak: bool
    timestamp_regression_flag: bool


@dataclass(frozen=True, slots=True)
class _Hop:
    position: int  # 1 = oldest hop, nearest the sender
    ip: IPAddress | None
    timestamp: datetime | None


def _hop_ip(received: str) -> IPAddress | None:
    """Connecting IP of a hop: the MTA's parenthesised TCP-info beats the client's HELO."""
    match = _FROM_CLAUSE_RE.match(received[:_MAX_RECEIVED_CHARS])
    if match is None:
        return None
    clause = _HELO_RE.sub(" ", match["clause"])
    depth = list(accumulate((1 if c == "(" else -1 if c == ")" else 0 for c in clause), initial=0))
    outside: list[IPAddress] = []
    for candidate in _IP_RE.finditer(clause):
        ip = parse_ip(candidate["v4"] or candidate["v6"])
        if ip is None:
            continue
        if depth[candidate.start()] > 0:
            return ip
        outside.append(ip)
    return outside[0] if outside else None


def _hop_timestamp(received: str) -> datetime | None:
    _, separator, date_text = received.rpartition(";")
    if not separator:
        return None
    try:
        stamp = parsedate_to_datetime(_COMMENT_RE.sub(" ", date_text).strip())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    # RFC 5322 "-0000" means "zone unknown" and yields a naive datetime: read it as UTC.
    return stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)


def _hops(msg: EmailMessage) -> list[_Hop]:
    try:
        received = [str(value) for value in msg.get_all("Received", [])]
    except Exception:
        logger.exception("Received headers could not be read", extra={"event": "route.header_error"})
        return []
    # Every MTA prepends its header, so file order is newest first.
    return [
        _Hop(position, _hop_ip(value), _hop_timestamp(value))
        for position, value in enumerate(reversed(received), start=1)
    ]


def _leaked_hops(hops: list[_Hop]) -> list[_Hop]:
    """Bogon hops strictly between the first and last public hop.

    Private hops before the first public one (LAN submission) or after the last
    (our own internal delivery) are normal.
    """
    public = [i for i, hop in enumerate(hops) if hop.ip is not None and not is_bogon(hop.ip)]
    if len(public) < 2:
        return []
    return [
        hop for hop in hops[public[0] + 1 : public[-1]] if hop.ip is not None and is_bogon(hop.ip)
    ]


def _regressions(hops: list[_Hop]) -> list[tuple[_Hop, _Hop, float]]:
    """(earlier hop, later hop, seconds backwards) where time runs back beyond clock skew."""
    dated = [(hop, hop.timestamp) for hop in hops if hop.timestamp is not None]
    return [
        (earlier, later, (earlier_ts - later_ts).total_seconds())
        for (earlier, earlier_ts), (later, later_ts) in pairwise(dated)
        if later_ts < earlier_ts - CLOCK_SKEW_TOLERANCE
    ]


def analyze_routing(msg: EmailMessage) -> RoutingFindings:
    """Hop count, mid-route private-address leaks and timestamp regression for ``msg``.

    The result unpacks straight into ``HeaderForensics`` alongside the identity findings.
    """
    hops = _hops(msg)
    leaked = _leaked_hops(hops)
    regressions = _regressions(hops)

    if leaked:
        logger.warning(
            "Private address between public hops",
            extra={
                "event": "route.private_ip_leak",
                "hops": [{"position": hop.position, "ip": str(hop.ip)} for hop in leaked],
            },
        )
    if regressions:
        logger.warning(
            "Received timestamps run backwards",
            extra={
                "event": "route.timestamp_regression",
                "regressions": [
                    {"from_position": a.position, "to_position": b.position, "seconds_backwards": s}
                    for a, b, s in regressions
                ],
            },
        )

    findings = RoutingFindings(
        route_hop_count=len(hops),
        private_ip_leak=bool(leaked),
        timestamp_regression_flag=bool(regressions),
    )
    logger.info(
        "Delivery route analyzed",
        extra={
            "event": "route.analyzed",
            **findings,
            "hops_with_ip": sum(hop.ip is not None for hop in hops),
            "hops_with_timestamp": sum(hop.timestamp is not None for hop in hops),
        },
    )
    return findings
