import email.policy
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime

import pytest

from src.core.config import get_settings
from src.forensics.auth_analyzer import analyze_identity
from src.forensics.route_analyzer import analyze_routing
from src.schemas import HeaderForensics

_PARSER = BytesParser(policy=email.policy.default)
T0 = datetime(2026, 10, 6, 10, 0, tzinfo=UTC)

# Globally routable addresses: documentation ranges such as 203.0.113.0/24 are
# themselves non-global, so they would read as bogons.
SENDER_IP = "185.220.101.4"
RELAY_IP = "40.107.22.55"
MX_IP = "209.85.220.41"


def _hop(tcp_info: str, when: datetime | str, *, helo: str = "relay.example.net") -> str:
    stamp = when if isinstance(when, str) else format_datetime(when)
    return f"from {helo} ({tcp_info}) by mx.example.org with ESMTPS id 4Xq; {stamp}"


def _route(*hops_oldest_first: str) -> EmailMessage:
    # Each MTA prepends its Received header, so the file lists the newest hop first.
    received = [f"Received: {hop}" for hop in reversed(hops_oldest_first)]
    raw = "\r\n".join((*received, "From: a@sender.example", "To: b@corp.example", "", "body", ""))
    return _PARSER.parsebytes(raw.encode("ascii"))


def test_four_hops_with_injected_private_ip_and_time_travel() -> None:
    msg = _route(
        _hop(f"unknown [{SENDER_IP}]", T0),
        _hop("relay [10.0.0.1]", T0 + timedelta(minutes=2)),
        _hop(f"relay2.example.net [{RELAY_IP}]", T0 + timedelta(minutes=2) - timedelta(minutes=5)),
        _hop(f"mail-sor-f41.google.com [{MX_IP}]", T0 + timedelta(minutes=3)),
    )

    findings = analyze_routing(msg)

    assert findings == {
        "route_hop_count": 4,
        "private_ip_leak": True,
        "timestamp_regression_flag": True,
        "extracted_ips": (SENDER_IP, "10.0.0.1", RELAY_IP, MX_IP),  # sender side first
    }


def test_clean_chronological_route_raises_no_flags() -> None:
    msg = _route(
        _hop(f"unknown [{SENDER_IP}]", T0),
        _hop(f"relay2.example.net [{RELAY_IP}]", T0 + timedelta(seconds=40)),
        _hop(f"mail-sor-f41.google.com [{MX_IP}]", T0 + timedelta(minutes=1)),
        _hop("mx.corp.example [52.100.1.1]", T0 + timedelta(minutes=2)),
    )

    findings = analyze_routing(msg)

    # Increasing times only read as increasing if the newest-first file order was reversed.
    assert findings == {
        "route_hop_count": 4,
        "private_ip_leak": False,
        "timestamp_regression_flag": False,
        "extracted_ips": (SENDER_IP, RELAY_IP, MX_IP, "52.100.1.1"),
    }


@pytest.mark.parametrize(
    ("seconds_backwards", "flagged"), [(30, False), (59, False), (60, False), (61, True), (300, True)]
)
def test_clock_skew_tolerance_is_sixty_seconds(seconds_backwards: int, flagged: bool) -> None:
    msg = _route(
        _hop(f"unknown [{SENDER_IP}]", T0),
        _hop(f"relay2.example.net [{RELAY_IP}]", T0 - timedelta(seconds=seconds_backwards)),
    )

    assert analyze_routing(msg)["timestamp_regression_flag"] is flagged


def test_mixed_timezones_are_compared_in_utc() -> None:
    # Local wall-clock times jump around (03:00, 10:01, 15:32, 12:03) but UTC is monotonic.
    msg = _route(
        _hop(f"unknown [{SENDER_IP}]", "Tue, 06 Oct 2026 03:00:00 -0700 (PDT)"),
        _hop(f"relay2.example.net [{RELAY_IP}]", "Tue, 06 Oct 2026 10:01:00 -0000"),  # naive
        _hop(f"mail-sor-f41.google.com [{MX_IP}]", "Tue, 06 Oct 2026 15:32:00 +0530 (IST)"),
        _hop("mx.corp.example [52.100.1.1]", "Tue, 06 Oct 2026 12:03:00 +0200"),
    )

    assert analyze_routing(msg)["timestamp_regression_flag"] is False


def test_private_hops_at_either_end_are_not_leaks() -> None:
    msg = _route(
        _hop("laptop.lan [192.168.1.20]", T0),  # LAN submission
        _hop(f"unknown [{SENDER_IP}]", T0 + timedelta(seconds=10)),
        _hop(f"mail-sor-f41.google.com [{MX_IP}]", T0 + timedelta(seconds=20)),
        _hop("edge.corp.internal [10.20.0.5]", T0 + timedelta(seconds=30)),  # our own delivery
        _hop("store.corp.internal [172.16.4.9]", T0 + timedelta(seconds=40)),
    )

    findings = analyze_routing(msg)

    # The two private hops at the receiving end are the receiver's own and are stripped;
    # the LAN hop at the start stays but sits before every public hop.
    assert findings["route_hop_count"] == 3
    assert findings["extracted_ips"] == ("192.168.1.20", SENDER_IP, MX_IP)
    assert findings["private_ip_leak"] is False


@pytest.mark.parametrize(
    ("middle_hop", "leak"),
    [
        pytest.param("from [10.0.0.1] (unknown [52.100.1.1])", False, id="postfix-helo-literal"),
        pytest.param("from [66.163.188.1] (port=443 helo=[10.0.0.7])", False, id="exim-helo"),
        pytest.param("from unknown (HELO 192.168.0.9) (66.163.188.1)", False, id="qmail-helo"),
        pytest.param("from relay (relay [10.0.0.1] (may be forged))", True, id="sendmail-nested"),
        pytest.param("from relay ([172.16.0.3]:52344 helo=relay)", True, id="exim-port"),
        pytest.param("from relay (relay [IPv6:fd12:3456::1])", True, id="ipv6-ula-literal"),
        pytest.param("from relay (::ffff:10.0.0.1)", True, id="ipv4-mapped-ipv6"),
        pytest.param("from relay (relay [100.64.12.1])", True, id="cgnat"),
    ],
)
def test_connecting_ip_beats_client_chosen_helo(middle_hop: str, leak: bool) -> None:
    msg = _route(
        _hop(f"unknown [{SENDER_IP}]", T0),
        f"{middle_hop} by mx.example.org with ESMTP; {format_datetime(T0 + timedelta(seconds=5))}",
        _hop(f"mail-sor-f41.google.com [IPv6:2a00:1450:4864:20::2b]", T0 + timedelta(seconds=9)),
    )

    assert analyze_routing(msg)["private_ip_leak"] is leak


def test_unparseable_hops_do_not_crash() -> None:
    msg = _route(
        "by mx.example.org (Postfix, from userid 1000) id 4Xq; Tue, 06 Oct 2026 10:00:00 +0000",
        "from relay (relay [999.1.1.1]) by mx.example.org; Tue, 99 Foo 2026 25:61:00 +9999",
        "(qmail 1234 invoked from network)",
        "",
    )

    # No hop shows a valid client outside mx.example.org's own domain, so the whole chain
    # reads as the receiver's and collapses to its oldest hop.
    assert analyze_routing(msg) == {
        "route_hop_count": 1,
        "private_ip_leak": False,
        "timestamp_regression_flag": False,
        "extracted_ips": (),  # 999.1.1.1 is not an address
    }


def test_message_without_received_headers() -> None:
    msg = _PARSER.parsebytes(b"From: a@sender.example\r\n\r\nbody\r\n")

    assert analyze_routing(msg) == {
        "route_hop_count": 0,
        "private_ip_leak": False,
        "timestamp_regression_flag": False,
        "extracted_ips": (),
    }


def test_identity_and_routing_merge_into_header_forensics() -> None:
    msg = _route(
        _hop(f"unknown [{SENDER_IP}]", T0),
        _hop("relay [10.0.0.1]", T0 + timedelta(minutes=2)),
        _hop(f"mail-sor-f41.google.com [{MX_IP}]", T0 + timedelta(seconds=30)),  # 90 s back
    )

    forensics = HeaderForensics(
        **analyze_identity(msg, get_settings().HIGH_RISK_BRAND_KEYWORDS),
        **analyze_routing(msg),
    )

    assert forensics.route_hop_count == 3
    assert forensics.private_ip_leak is True
    assert forensics.timestamp_regression_flag is True
