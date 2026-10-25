"""Delivery-route forensics over the Received chain.

Hops are evaluated oldest first. Each Received header is written by the receiving
MTA of that hop, so everything below our boundary is only as trustworthy as the
sender: forged hops are exactly what these checks look for.

Only the sender-side path is scored. Hops the receiving mail system adds after it
accepted the message (Gmail's ``by``-only handoffs, a content filter on loopback,
internal relays) describe the recipient's provider, not the sender, and would let
a model learn which mailbox a training email came from instead of whether it is
phishing. They are stripped down to the receiver's entry hop, which is kept: its
client IP is the last address the sender side presented.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from itertools import accumulate, pairwise
from typing import Final, TypedDict

from src.core.domains import registered_domain
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
_BY_HOST_RE: Final = re.compile(r"(?: ^ | \s ) by \s+ (?P<host> [^\s;()\[\]]+ )", re.IGNORECASE | re.VERBOSE)
# The name the receiving MTA resolved for the client, as in Postfix's "(rdns [ip])". Unlike
# the HELO name it was not chosen by the client; "unknown" (no dot) never matches.
_RDNS_RE: Final = re.compile(
    r""" \( \s* (?P<name> [a-z0-9] [a-z0-9-]* (?: \. [a-z0-9-]+ )+ ) \.? \s+ \[ """, re.IGNORECASE | re.VERBOSE
)


class RoutingFindings(TypedDict):
    """The ``HeaderForensics`` fields owned by route analysis."""

    route_hop_count: int
    private_ip_leak: bool
    timestamp_regression_flag: bool
    # Connecting IP of each hop, oldest (nearest the sender) first; hops without one are skipped.
    extracted_ips: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Hop:
    position: int  # 1 = oldest hop, nearest the sender
    ip: IPAddress | None
    timestamp: datetime | None
    has_from: bool  # False for "by"-only headers: an MTA's own handoff or local delivery
    by_domain: str | None  # registered domain of the receiving host (None for IP literals)
    rdns_domain: str | None  # registered domain the receiving MTA resolved for the client


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


def _parse_hop(position: int, received: str) -> _Hop:
    text = received[:_MAX_RECEIVED_CHARS]
    from_clause = _FROM_CLAUSE_RE.match(text)
    by_match = _BY_HOST_RE.search(text, from_clause.end() if from_clause else 0)
    by_host = by_match["host"] if by_match else None
    rdns = _RDNS_RE.search(from_clause["clause"]) if from_clause else None
    return _Hop(
        position=position,
        ip=_hop_ip(received),
        timestamp=_hop_timestamp(received),
        has_from=from_clause is not None,
        by_domain=None if by_host is None or parse_ip(by_host) else registered_domain(by_host),
        rdns_domain=registered_domain(rdns["name"]) if rdns else None,
    )


def _hops(msg: EmailMessage) -> list[_Hop]:
    try:
        received = [str(value) for value in msg.get_all("Received", [])]
    except Exception:
        logger.exception("Received headers could not be read", extra={"event": "route.header_error"})
        return []
    # Every MTA prepends its header, so file order is newest first.
    return [_parse_hop(position, value) for position, value in enumerate(reversed(received), start=1)]


def _sender_side(hops: list[_Hop]) -> tuple[list[_Hop], int]:
    """(hops up to and including the receiver's entry hop, number of receiver hops dropped).

    Walking from the newest hop, a hop belongs to the receiving system when it has no
    ``from`` clause, when its client is a private or loopback address, or when both its
    receiving host and the resolved client name sit in the receiver's domain (named by
    the newest hop that has a ``from`` clause). The first hop that is none of these is
    the entry hop. The client-chosen HELO name is never consulted, so a sender cannot
    claim to be the receiver and get the real entry hop stripped. The resolved name is
    trusted as the receiver recorded it; MTAs that print unverified PTR names (Postfix
    prints only forward-confirmed ones, else "unknown") weaken that guarantee.
    """
    receiver: str | None = None
    for index in range(len(hops) - 1, -1, -1):
        hop = hops[index]
        if not hop.has_from:
            continue
        if receiver is None:
            receiver = hop.by_domain
        same_receiver = hop.by_domain is not None and hop.by_domain == receiver
        internal = (hop.ip is not None and is_bogon(hop.ip)) or (
            same_receiver and (hop.ip is None or hop.rdns_domain == receiver)
        )
        if not internal:
            return hops[: index + 1], len(hops) - index - 1
    # Every hop is the receiver's own (e.g. same-provider mail): keep the oldest as the hand-off.
    return hops[:1], max(len(hops) - 1, 0)


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

    Computed over the sender-side path only (see the module docstring). The result
    unpacks straight into ``HeaderForensics`` alongside the identity findings.
    """
    hops, receiver_hops = _sender_side(_hops(msg))
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
        extracted_ips=tuple(str(hop.ip) for hop in hops if hop.ip is not None),
    )
    logger.info(
        "Delivery route analyzed",
        extra={
            "event": "route.analyzed",
            **findings,
            "receiver_hops_stripped": receiver_hops,
            "hops_with_ip": len(findings["extracted_ips"]),
            "hops_with_timestamp": sum(hop.timestamp is not None for hop in hops),
        },
    )
    return findings
