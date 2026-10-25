"""Receiver-side hop stripping: route features must describe the sender's path only.

Training corpora come from different mailboxes (a hosted provider for phishing, Gmail
or a corporate server for legitimate mail). If each receiver's own internal hops
counted, a model could learn which mailbox an email was collected from instead of
whether it is phishing.
"""

import email.policy
import json
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

import pytest

from src.core.domains import registered_domain
from src.core.logger import LOG_FILE_NAME, configure_logging, shutdown_logging
from src.forensics.route_analyzer import analyze_routing

_PARSER = BytesParser(policy=email.policy.default)

# The sender side, oldest first: a kit host, a forged private hop, the outbound relay.
SENDER_PATH = [
    "from kit.attacker.example (unknown [185.220.101.4]) by internal.attacker.example"
    " with ESMTP id A1; Tue, 06 Oct 2026 10:00:00 +0000",
    "from internal.attacker.example (internal [10.0.0.1]) by out.attacker.example"
    " with ESMTP id B2; Tue, 06 Oct 2026 10:01:00 +0000",
]
EXPECTED = {
    "route_hop_count": 3,  # the two sender hops plus the receiver's entry hop
    "private_ip_leak": True,
    "timestamp_regression_flag": False,
    "extracted_ips": ("185.220.101.4", "10.0.0.1", "194.26.29.10"),
}

# Each receiver's hops, oldest (its entry hop) first.
RECEIVERS = {
    "hosted": [  # Nazario's provider: the entry hop and nothing else
        "from out.attacker.example (out.attacker.example [194.26.29.10]) by imf16.b.hostedemail.com"
        " (Postfix) with ESMTP id C3; Tue, 06 Oct 2026 10:02:00 +0000",
    ],
    "gmail": [  # entry at mx.google.com, then Google's "by"-only internal handoffs
        "from out.attacker.example (out.attacker.example. [194.26.29.10]) by mx.google.com"
        " with ESMTPS id x1; Tue, 06 Oct 2026 10:02:00 +0000",
        "by 2002:a05:6022:4204:b0:9f:1a2b:3c4d with SMTP id y2; Tue, 06 Oct 2026 10:02:01 +0000",
        "by 2002:a05:6022:4204:b0:9f:1a2b:3c4e with SMTP id z3; Tue, 06 Oct 2026 10:02:01 +0000",
    ],
    "corporate": [  # Postfix MX, a loopback content filter, then internal relays
        "from out.attacker.example (out.attacker.example [194.26.29.10]) by mx1.corp.example"
        " (Postfix) with ESMTP id D4; Tue, 06 Oct 2026 10:02:00 +0000",
        "from localhost (localhost [127.0.0.1]) by mx1.corp.example (Postfix) with ESMTP id E5;"
        " Tue, 06 Oct 2026 10:02:02 +0000",
        "from mx1.corp.example (mx1.corp.example [52.100.9.9]) by hub.corp.example"
        " with ESMTPS id F6; Tue, 06 Oct 2026 10:02:03 +0000",
        "from hub.corp.example (hub.corp.example [10.1.1.1]) by store.corp.example"
        " with LMTP id G7; Tue, 06 Oct 2026 10:02:04 +0000",
    ],
}


def _message(chain_oldest_first: list[str]) -> EmailMessage:
    received = [f"Received: {hop}" for hop in reversed(chain_oldest_first)]
    raw = "\r\n".join((*received, "From: a@attacker.example", "To: v@corp.example", "", "body", ""))
    return _PARSER.parsebytes(raw.encode("ascii"))


@pytest.mark.parametrize("receiver", sorted(RECEIVERS))
def test_same_sender_path_scores_identically_whoever_received_it(receiver: str) -> None:
    assert analyze_routing(_message(SENDER_PATH + RECEIVERS[receiver])) == EXPECTED


def test_stripped_receiver_hops_are_logged(tmp_path: Path) -> None:
    shutdown_logging()
    configure_logging(log_dir=tmp_path, level="DEBUG")
    try:
        for receiver in ("hosted", "gmail", "corporate"):
            analyze_routing(_message(SENDER_PATH + RECEIVERS[receiver]))
    finally:
        shutdown_logging()

    records = [json.loads(line) for line in (tmp_path / LOG_FILE_NAME).read_text("utf-8").splitlines()]
    stripped = [r["receiver_hops_stripped"] for r in records if r.get("event") == "route.analyzed"]
    assert stripped == [0, 2, 3]


def test_spoofed_helo_cannot_get_the_real_entry_hop_stripped() -> None:
    # The client claims to be the receiver's own host; the MTA resolved nothing for it.
    entry = (
        "from imf16.b.hostedemail.com (unknown [194.26.29.10]) by imf16.b.hostedemail.com"
        " (Postfix) with ESMTP id C3; Tue, 06 Oct 2026 10:02:00 +0000"
    )

    findings = analyze_routing(_message(SENDER_PATH + [entry]))

    assert findings["extracted_ips"] == EXPECTED["extracted_ips"]
    assert findings["route_hop_count"] == 3


def test_forged_hops_below_the_entry_stay_visible() -> None:
    # Stripping stops at the entry hop, so a sender-side clock jump is still caught.
    forged = [
        SENDER_PATH[0],
        SENDER_PATH[1].replace("10:01:00", "09:50:00"),
    ]

    findings = analyze_routing(_message(forged + RECEIVERS["gmail"]))

    assert findings["timestamp_regression_flag"] is True
    assert findings["private_ip_leak"] is True


def test_same_provider_mail_keeps_a_single_hand_off_hop() -> None:
    # Gmail to Gmail: every hop is Google's, so only the oldest (submission) hop remains.
    chain = [
        "from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com"
        " with SMTPS id a1; Tue, 06 Oct 2026 10:00:00 +0000",
        "by 2002:a05:6022:4204:b0:9f:1a2b:3c4d with SMTP id b2; Tue, 06 Oct 2026 10:00:01 +0000",
    ]

    findings = analyze_routing(_message(chain))

    assert findings["route_hop_count"] == 1
    assert findings["extracted_ips"] == ("209.85.220.41",)


def test_mail_without_received_headers_is_untouched() -> None:
    assert analyze_routing(_message([]))["route_hop_count"] == 0


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("mail.evil.co.uk", "evil.co.uk"),
        ("imf16.b.hostedemail.com", "hostedemail.com"),
        ("edge.corp.internal", "corp.internal"),  # no public suffix: last two labels
        ("mx.corp.example.", "corp.example"),
        ("192.0.2.1", "192.0.2.1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("localhost", "localhost"),
        ("", None),
        (None, None),
    ],
)
def test_registered_domain(host: str | None, expected: str | None) -> None:
    assert registered_domain(host) == expected
