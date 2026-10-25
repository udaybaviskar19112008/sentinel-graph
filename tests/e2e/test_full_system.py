"""Whole-system validation through the public WebSocket API, without the Vite UI.

Unlike tests/test_ws_manager.py, nothing is injected here: the app starts through
its own lifespan, so ``AnalysisEngines.load()`` builds every engine from
``MODELS_DIR``, and the sandbox is real Chromium behind the real egress proxy.
``MODELS_DIR`` points at an empty temp directory, so each engine generates its
placeholder exactly as a fresh deployment would: the scores therefore come from
the synthetic fusion model, not from a trained one. These tests prove the wiring
and the decision path, not detection quality on real mail.
"""

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from app.main import STREAM_PATH, create_app
from src.core.config import get_settings
from src.schemas import ThreatAssessment

pytestmark = pytest.mark.e2e

STREAM_TIMEOUT_S = 120.0

# ".invalid" can never resolve (RFC 2606), so detonation fails fast and offline.
# Newest hop first. The top hop is our own edge-to-inbox relay and is stripped as
# receiver-internal; below it, the sender side forges a private hop and a clock jump.
PHISHING_EML = (
    "Received: from mx-edge.corp.example (mx-edge.corp.example [40.107.22.55])\r\n"
    "\tby inbox.corp.example with ESMTPS id 9F2C1; Tue, 06 Oct 2026 10:02:50 +0000\r\n"
    "Received: from relay.bulk-sender.invalid (relay.bulk-sender.invalid [194.26.29.10])\r\n"
    "\tby mx-edge.corp.example with ESMTPS id 5E77A; Tue, 06 Oct 2026 10:02:41 +0000\r\n"
    "Received: from internal.bulk-sender.invalid (internal [10.0.0.1])\r\n"
    "\tby relay.bulk-sender.invalid with ESMTP id 7A11B; Tue, 06 Oct 2026 09:55:12 +0000\r\n"
    "Received: from kit.bulk-sender.invalid (unknown [185.220.101.4])\r\n"
    "\tby internal.bulk-sender.invalid with ESMTP id 3C0DE; Tue, 06 Oct 2026 10:01:03 +0000\r\n"
    "Authentication-Results: mx-edge.corp.example;\r\n"
    "\tspf=fail (sender IP is 185.220.101.4) smtp.mailfrom=apple-id-support.invalid;\r\n"
    "\tdkim=none (message not signed) header.d=none;\r\n"
    "\tdmarc=fail action=reject header.from=apple-id-support.invalid\r\n"
    'From: "Apple Support" <security@apple-id-support.invalid>\r\n'
    "Reply-To: billing@collector.invalid\r\n"
    "To: victim@corp.example\r\n"
    "Subject: =?utf-8?b?WW91ciBBcHBsZSBJRCBoYXMgYmVlbiBsb2NrZWQ=?=\r\n"
    "Date: Tue, 06 Oct 2026 10:01:00 +0000\r\n"
    "Message-ID: <e2e-phish-0001@apple-id-support.invalid>\r\n"
    "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/alternative; boundary="b1"\r\n'
    "\r\n"
    "--b1\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Your Apple ID is locked. Verify at https://secure-apple-id.invalid/login\r\n"
    "--b1\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "\r\n"
    '<html><body><p>Your Apple ID is locked.</p><a href="https://secure-apple-id.invalid/login">'
    "Verify now</a></body></html>\r\n"
    "--b1--\r\n"
).encode("ascii")

BENIGN_EML = (
    "Received: from mail.partner.example (mail.partner.example [209.85.220.41])\r\n"
    "\tby inbox.corp.example with ESMTPS id 1B2C3; Tue, 06 Oct 2026 11:00:05 +0000\r\n"
    "Authentication-Results: mx-edge.corp.example; spf=pass smtp.mailfrom=partner.example;\r\n"
    "\tdkim=pass header.d=partner.example; dmarc=pass header.from=partner.example\r\n"
    "From: Priya Shah <priya@partner.example>\r\n"
    "To: team@corp.example\r\n"
    "Subject: Minutes from Tuesday\r\n"
    "Date: Tue, 06 Oct 2026 11:00:00 +0000\r\n"
    "Message-ID: <minutes-0042@partner.example>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Attached are the notes from Tuesday's sync. No action needed.\r\n"
).encode("ascii")


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    """The real app (real lifespan, real engine loading) over a fresh, empty MODELS_DIR."""
    root = tmp_path_factory.mktemp("e2e")
    with pytest.MonkeyPatch.context() as env:
        env.setenv("SOC_MODELS_DIR", str(root / "models"))
        env.setenv("SOC_LOG_DIR", str(root / "logs"))
        get_settings.cache_clear()
        try:
            with TestClient(create_app()) as test_client:
                yield test_client
        finally:
            get_settings.cache_clear()


def _stream(client: TestClient, raw_email: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Send one email and collect telemetry until COMPLETE; return (events, COMPLETE event)."""
    events: list[dict[str, Any]] = []
    deadline = time.monotonic() + STREAM_TIMEOUT_S
    with client.websocket_connect(STREAM_PATH) as websocket:
        websocket.send_bytes(raw_email)
        while True:
            if time.monotonic() > deadline:
                pytest.fail(f"no COMPLETE within {STREAM_TIMEOUT_S}s; last phases: {[e.get('phase') for e in events[-5:]]}")
            try:
                event = websocket.receive_json()
            except WebSocketDisconnect as closed:
                pytest.fail(f"server closed the stream early (code {closed.code}); events: {events[-3:]}")
            assert "error" not in event, event["error"]
            events.append(event)
            if event["phase"] == "COMPLETE":
                return events, event


def _history(client: TestClient) -> list[dict[str, Any]]:
    response = client.get("/api/v1/history/scans", params={"limit": 200})
    assert response.status_code == 200
    scans: list[dict[str, Any]] = response.json()
    return scans


def test_websocket_phishing_detonation(client: TestClient) -> None:
    before = _history(client)
    events, final_payload = _stream(client, PHISHING_EML)

    phases = [event["phase"] for event in events]
    # The spec's "GRAPH" stage is streamed as TOPOLOGY.
    for phase in ("RECEIVED", "TIER_1", "VISION", "TOPOLOGY", "SLM_REASONING", "SLM_VERDICT", "COMPLETE"):
        assert phase in phases, f"{phase} missing from {phases}"
    assert phases[0] == "RECEIVED" and phases[-1] == "COMPLETE"

    assessment = ThreatAssessment.model_validate(final_payload["assessment"])
    header = assessment.header_forensics
    assert (header.spf, header.dkim, header.dmarc) == ("fail", "none", "fail")
    assert header.impersonated_brand == "apple" and header.display_name_spoof_risk == 1.0
    assert header.private_ip_leak is True and header.timestamp_regression_flag is True
    # Sender side only: our edge relay (40.107.22.55) was stripped as receiver-internal.
    assert header.extracted_ips == ("185.220.101.4", "10.0.0.1", "194.26.29.10")
    assert header.subject == "Your Apple ID has been locked"

    # The lure was handed to the real sandbox; ".invalid" cannot resolve, so nothing was captured.
    detonation = next(e for e in events if e.get("status") == "Sandbox detonation finished")
    assert detonation["url"] == "https://secure-apple-id.invalid/login" and detonation["captured"] is False
    assert assessment.vision_forensics is None

    assert assessment.topology_forensics is not None
    assert assessment.topology_forensics.graph_nodes_count == 1 + 3 + 1 + 1
    assert assessment.overall_risk > 50
    assert assessment.analyst_trace.strip()
    assert final_payload["verdict"] in {"BENIGN", "SUSPICIOUS", "PHISHING", "CRITICAL"}
    assert final_payload["contributions"], "SHAP attribution missing"
    # The scan is in the history API exactly once, matching what was streamed. (The suite
    # shares one test database, so this checks the *new* rows rather than a total of 1.)
    after = _history(client)
    assert len(after) == len(before) + 1
    saved = after[0]
    assert saved["id"] == final_payload["scan_id"]
    assert saved["overall_risk"] == assessment.overall_risk
    assert saved["analyst_trace"] == assessment.analyst_trace
    assert saved["final_verdict"] == final_payload["verdict"]
    assert saved["subject"] == "Your Apple ID has been locked"
    assert "security@apple-id-support.invalid" in saved["sender"]
    saved_indicators = {(i["type"], i["value"]) for i in saved["indicators"]}
    assert {("IP", ip) for ip in header.extracted_ips} <= saved_indicators
    assert ("URL", "https://secure-apple-id.invalid/login") in saved_indicators
    # And the campaign pivot finds it from its sender IP and its lure URL.
    for indicator in ("185.220.101.4", "https://secure-apple-id.invalid/login"):
        pivot = client.get(f"/api/v1/history/indicators/{indicator}").json()
        assert saved["id"] in [scan["id"] for scan in pivot], indicator
    # Every engine came up as a placeholder; the payload must say so to the analyst.
    assert final_payload["model_status"] == {
        "vision_placeholder": True,
        "memae_placeholder": True,
        "zero_day_calibrated": False,
        "fusion_dummy": True,
        "slm_dummy": True,
    }


def test_benign_email_scores_below_phishing(client: TestClient) -> None:
    _, phishing = _stream(client, PHISHING_EML)
    benign_events, benign = _stream(client, BENIGN_EML)

    assert not any(e.get("status") == "Sandbox detonation started" for e in benign_events)  # no URL
    benign_assessment = ThreatAssessment.model_validate(benign["assessment"])
    assert benign_assessment.header_forensics.impersonated_brand is None
    assert benign_assessment.overall_risk < phishing["assessment"]["overall_risk"]


def test_logs_from_the_whole_run_land_in_the_configured_log_dir(client: TestClient) -> None:
    log_file = Path(get_settings().LOG_DIR) / "system.log"

    assert log_file.is_file() and log_file.stat().st_size > 0
