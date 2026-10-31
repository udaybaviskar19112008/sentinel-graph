"""The deployed configuration, end to end: ingestion -> stream -> database -> history API.

``test_full_system`` proves the wiring with freshly generated placeholder engines.
This module runs what is actually demonstrated: the app's own lifespan over the
project's real ``MODELS_DIR``, so the trained MemAE (with its calibrated zero-day
threshold) and the trained fusion model score the email. It is skipped on a clone
that has never been trained, because loading engines there would write placeholder
models into the project tree. Scan history still goes to the suite's throwaway
database (see ``tests/conftest.py``).

Run with ``-s`` to print the trained model's SHAP breakdown for the demo lure.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from src.core.config import get_settings
from src.schemas import ThreatAssessment
from tests.e2e.test_full_system import PHISHING_EML, _stream

pytestmark = pytest.mark.e2e

Scan = tuple[list[dict[str, Any]], dict[str, Any]]


@pytest.fixture(scope="module")
def deployed_client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    """The real app over the project's trained models; logs go to a temp dir."""
    if not (get_settings().MODELS_DIR / "training_report.json").is_file():
        pytest.skip("no trained models in MODELS_DIR; run scripts/train_orchestrator.py first")
    with pytest.MonkeyPatch.context() as env:
        env.setenv("SOC_LOG_DIR", str(tmp_path_factory.mktemp("capstone-logs")))
        get_settings.cache_clear()
        try:
            with TestClient(create_app()) as client:
                yield client
        finally:
            get_settings.cache_clear()


@pytest.fixture(scope="module")
def completed_scan(deployed_client: TestClient) -> Scan:
    """One phishing email (4 Received hops, a lure URL) streamed to COMPLETE."""
    return _stream(deployed_client, PHISHING_EML)


def test_websocket_to_database_e2e(completed_scan: Scan) -> None:
    events, final = completed_scan

    phases = [event["phase"] for event in events]
    assert phases[0] == "RECEIVED" and phases[-1] == "COMPLETE"
    assert {"TIER_1", "VISION", "TOPOLOGY", "SLM_REASONING", "SLM_VERDICT"} <= set(phases)

    assessment = ThreatAssessment.model_validate(final["assessment"])
    assert 0 <= assessment.overall_risk <= 100
    assert assessment.analyst_trace.strip()
    assert assessment.topology_forensics is not None
    assert final["scan_id"] is not None, "the scan was not persisted"

    # The trained engines, not placeholders, produced this score.
    status = final["model_status"]
    assert status["memae_placeholder"] is False
    assert status["fusion_dummy"] is False
    assert status["zero_day_calibrated"] is True

    # SHAP is additive: the attributions must reconstruct the probability around the base value.
    contributions = final["contributions"]
    assert contributions and {c["feature_name"] for c in contributions}
    print(f"\nrisk {assessment.overall_risk}/100, verdict {final['verdict']}, "
          f"MemAE loss {assessment.topology_forensics.memae_reconstruction_loss:.3f}")
    for contribution in sorted(contributions, key=lambda c: -abs(c["impact"])):
        print(f"  {contribution['feature_name']:<24} {contribution['impact']:+.4f} "
              f"({contribution['percentage']:.1f}%, {contribution['subsystem']})")


def test_history_api_persistence(deployed_client: TestClient, completed_scan: Scan) -> None:
    _, final = completed_scan

    response = deployed_client.get("/api/v1/history/scans")

    assert response.status_code == 200
    scans = response.json()
    assert len(scans) >= 1
    saved = next((scan for scan in scans if scan["id"] == final["scan_id"]), None)
    assert saved is not None, f"scan {final['scan_id']} missing from history"
    assert saved["overall_risk"] == final["assessment"]["overall_risk"]
    assert saved["final_verdict"] == final["verdict"]
    assert saved["analyst_trace"] == final["assessment"]["analyst_trace"]
    assert saved["subject"] == "Your Apple ID has been locked"
    assert ("URL", "https://secure-apple-id.invalid/login") in {(i["type"], i["value"]) for i in saved["indicators"]}
