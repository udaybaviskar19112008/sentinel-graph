"""Stage 1B: the extractors together on one hostile email."""

import email.policy
import json
from email.parser import BytesParser
from pathlib import Path

from src.core.config import get_settings
from src.core.logger import LOG_FILE_NAME, configure_logging, shutdown_logging
from src.extractors.mime_parser import unpack_email
from src.forensics.auth_analyzer import analyze_identity
from src.forensics.route_analyzer import analyze_routing
from src.schemas import AuthStatus, HeaderForensics

SENDER_IP = "185.220.101.4"
INTERNAL_IP = "10.0.0.1"
EDGE_IP = "40.107.22.55"

# Newest hop first, as MTAs prepend. The DKIM-Signature claims paypal.com, but our MX
# verified it and recorded a failure; the multipart never closes its boundary.
HOSTILE_EML = (
    f"Received: from edge.relay.example (edge.relay.example [{EDGE_IP}])\r\n"
    "\tby mx.corp.example with ESMTPS id C3; Tue, 06 Oct 2026 10:02:00 +0000\r\n"
    f"Received: from internal.relay.example (internal [{INTERNAL_IP}])\r\n"
    "\tby edge.relay.example with ESMTP id B2; Tue, 06 Oct 2026 10:01:00 +0000\r\n"
    f"Received: from kit.attacker.example (unknown [{SENDER_IP}])\r\n"
    "\tby internal.relay.example with ESMTP id A1; Tue, 06 Oct 2026 10:00:00 +0000\r\n"
    "DKIM-Signature: v=1; a=rsa-sha256; d=paypal.com; s=pp-dkim1; h=from:subject;\r\n"
    "\tbh=ZmFrZQ==; b=Zm9yZ2VkIHNpZ25hdHVyZQ==\r\n"
    "Authentication-Results: mx.corp.example; spf=softfail smtp.mailfrom=paypal.com;\r\n"
    "\tdkim=fail (body hash did not verify) header.d=paypal.com header.s=pp-dkim1;\r\n"
    "\tdmarc=fail (p=REJECT) header.from=paypal.com\r\n"
    'From: "PayPal" <service@paypal.com>\r\n'
    "To: victim@corp.example\r\n"
    "Subject: Account limited\r\n"
    "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/alternative; boundary="b1"\r\n'
    "\r\n"
    "--b1\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "\r\n"
    '<html><a href="https://paypa1-resolution.example/login">Restore access</a></html>\r\n'
).encode("ascii")


def _parse(raw: bytes) -> object:
    return BytesParser(policy=email.policy.default).parsebytes(raw)


def test_routing_ips_are_extracted_sender_first() -> None:
    message, _, _, _ = unpack_email(HOSTILE_EML)

    routing = analyze_routing(message)

    assert routing["extracted_ips"] == (SENDER_IP, INTERNAL_IP, EDGE_IP)
    assert routing["route_hop_count"] == 3
    assert routing["private_ip_leak"] is True  # 10.0.0.1 between two public hops


def test_forged_dkim_signature_is_reported_as_failed() -> None:
    message, _, _, _ = unpack_email(HOSTILE_EML)

    identity = analyze_identity(message, get_settings().HIGH_RISK_BRAND_KEYWORDS)

    # A DKIM-Signature header proves nothing on its own; the receiver's verdict is what counts.
    assert identity["dkim"] is AuthStatus.FAIL
    assert identity["spf"] is AuthStatus.FAIL
    assert identity["dmarc"] is AuthStatus.FAIL
    assert identity["from_domain"] == "paypal.com"


def test_malformed_mime_still_yields_the_lure_and_logs_the_defect(tmp_path: Path) -> None:
    shutdown_logging()
    configure_logging(log_dir=tmp_path, level="DEBUG")
    try:
        _, _, html, _ = unpack_email(HOSTILE_EML)
    finally:
        shutdown_logging()

    assert "https://paypa1-resolution.example/login" in html
    records = [json.loads(line) for line in (tmp_path / LOG_FILE_NAME).read_text("utf-8").splitlines()]
    (defects,) = [r for r in records if r.get("event") == "mime.defects"]
    assert "CloseBoundaryNotFoundDefect" in defects["defect_classes"]


def test_ipv6_and_mapped_hops_keep_their_place_in_order() -> None:
    raw = (
        "Received: from c.example (c.example [IPv6:2a00:1450:4864:20::2b]) by mx.corp.example;"
        " Tue, 06 Oct 2026 10:02:00 +0000\r\n"
        "Received: from b.example (::ffff:52.100.1.1) by c.example; Tue, 06 Oct 2026 10:01:00 +0000\r\n"
        "Received: by a.example (Postfix, from userid 1000); Tue, 06 Oct 2026 10:00:30 +0000\r\n"
        f"Received: from a.example (a.example [{SENDER_IP}]) by b.example; Tue, 06 Oct 2026 10:00:00 +0000\r\n"
        "From: a@a.example\r\n\r\nbody\r\n"
    ).encode("ascii")

    routing = analyze_routing(unpack_email(raw)[0])

    # The local-submission hop names no IP and is skipped; mapped IPv6 collapses to IPv4.
    assert routing["extracted_ips"] == (SENDER_IP, "52.100.1.1", "2a00:1450:4864:20::2b")
    assert routing["route_hop_count"] == 4


def test_extracted_ips_survive_the_contract_and_a_json_round_trip() -> None:
    message, _, _, _ = unpack_email(HOSTILE_EML)
    header = HeaderForensics(
        **analyze_identity(message, get_settings().HIGH_RISK_BRAND_KEYWORDS), **analyze_routing(message)
    )

    assert header.extracted_ips == (SENDER_IP, INTERNAL_IP, EDGE_IP)
    assert HeaderForensics.model_validate(json.loads(header.model_dump_json())) == header
