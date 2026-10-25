from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.main import create_app
from src.core.config import get_settings
from src.core.orchestrator import AnalysisEngines
from src.models.db_models import Base, EmailScanRecord, ExtractedIndicator, IndicatorType
from src.schemas import VerdictLevel

T0 = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
CAMPAIGN_IP = "185.220.101.4"
LURE_URL = "https://secure-apple-id.invalid/login?u=1"


def _scan(minutes: int, risk: int, verdict: VerdictLevel, *indicators: tuple[IndicatorType, str]) -> EmailScanRecord:
    return EmailScanRecord(
        timestamp=T0 + timedelta(minutes=minutes),
        subject=f"scan at +{minutes}m",
        sender='"Apple Support" <x@evil.example>',
        final_verdict=verdict,
        overall_risk=risk,
        analyst_trace="trace",
        indicators=[ExtractedIndicator(type=kind, value=value) for kind, value in indicators],
    )


@pytest.fixture
def client(engines: AnalysisEngines, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """The real app over a private database seeded with four scans (two share a campaign IP)."""
    database = tmp_path / "history.db"
    with Session(create_engine(f"sqlite:///{database.as_posix()}")) as seed:
        Base.metadata.create_all(seed.get_bind())
        seed.add_all(
            [
                _scan(0, 10, VerdictLevel.BENIGN, (IndicatorType.DOMAIN, "partner.example")),
                _scan(10, 55, VerdictLevel.SUSPICIOUS, (IndicatorType.IP, CAMPAIGN_IP)),
                _scan(20, 80, VerdictLevel.PHISHING, (IndicatorType.IP, "203.0.113.9")),
                _scan(30, 95, VerdictLevel.CRITICAL, (IndicatorType.IP, CAMPAIGN_IP), (IndicatorType.URL, LURE_URL)),
            ]
        )
        seed.commit()
    monkeypatch.setenv("SOC_DATABASE_URL", f"sqlite+aiosqlite:///{database.as_posix()}")
    get_settings.cache_clear()
    with TestClient(create_app(engines)) as test_client:
        yield test_client
    monkeypatch.undo()
    get_settings.cache_clear()


def _subjects(scans: list[dict[str, Any]]) -> list[str]:
    return [scan["subject"] for scan in scans]


def test_scans_are_listed_newest_first_with_indicators(client: TestClient) -> None:
    scans = client.get("/api/v1/history/scans").json()

    assert _subjects(scans) == ["scan at +30m", "scan at +20m", "scan at +10m", "scan at +0m"]
    newest = scans[0]
    assert newest["final_verdict"] == "CRITICAL" and newest["overall_risk"] == 95
    assert datetime.fromisoformat(newest["timestamp"]) == T0 + timedelta(minutes=30)
    assert newest["indicators"] == [
        {"type": "IP", "value": CAMPAIGN_IP, "malicious_flag": False},
        {"type": "URL", "value": LURE_URL, "malicious_flag": False},
    ]


def test_pagination_and_risk_filter(client: TestClient) -> None:
    page = client.get("/api/v1/history/scans", params={"skip": 1, "limit": 2}).json()
    risky = client.get("/api/v1/history/scans", params={"min_risk": 80}).json()

    assert _subjects(page) == ["scan at +20m", "scan at +10m"]
    assert [scan["overall_risk"] for scan in risky] == [95, 80]


@pytest.mark.parametrize(
    "params", [{"limit": 0}, {"limit": 201}, {"skip": -1}, {"min_risk": 101}, {"min_risk": -1}]
)
def test_out_of_range_paging_is_rejected(client: TestClient, params: dict[str, int]) -> None:
    assert client.get("/api/v1/history/scans", params=params).status_code == 422


def test_ip_pivot_finds_every_scan_in_the_campaign(client: TestClient) -> None:
    scans = client.get(f"/api/v1/history/indicators/{CAMPAIGN_IP}").json()

    assert _subjects(scans) == ["scan at +30m", "scan at +10m"]


def test_url_pivot_keeps_slashes_in_the_path(client: TestClient) -> None:
    # Slashes may stay raw thanks to {indicator_value:path}; "?" must be percent-encoded.
    scans = client.get("/api/v1/history/indicators/" + quote(LURE_URL, safe=":/")).json()

    assert _subjects(scans) == ["scan at +30m"]


def test_indicator_type_filter_and_unknown_values(client: TestClient) -> None:
    assert client.get("/api/v1/history/indicators/partner.example", params={"type": "IP"}).json() == []
    assert len(client.get("/api/v1/history/indicators/partner.example", params={"type": "DOMAIN"}).json()) == 1
    assert client.get("/api/v1/history/indicators/198.51.100.77").json() == []


def test_history_is_not_readable_cross_origin_by_default(client: TestClient) -> None:
    hostile = client.get("/api/v1/history/scans", headers={"Origin": "https://evil.example"})
    dashboard = client.get("/api/v1/history/scans", headers={"Origin": "http://localhost:5173"})

    # The browser withholds a response without a matching ACAO header from the page.
    assert "access-control-allow-origin" not in hostile.headers
    assert dashboard.headers["access-control-allow-origin"] == "http://localhost:5173"
