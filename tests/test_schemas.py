import json
from typing import Any

import pytest
from pydantic import ValidationError

from src.schemas import AuthStatus, HeaderForensics, ThreatAssessment, TopologyForensics, VisionForensics


def _assessment() -> ThreatAssessment:
    return ThreatAssessment(
        header_forensics=HeaderForensics(
            spf=AuthStatus.FAIL,
            dkim=AuthStatus.NONE,
            dmarc=AuthStatus.FAIL,
            arc=AuthStatus.PASS,
            route_hop_count=3,
            private_ip_leak=True,
            timestamp_regression_flag=False,
            display_name_spoof_risk=1.0,
            impersonated_brand="apple",
        ),
        vision_forensics=VisionForensics(
            screenshot_hash="ab" * 32, visual_spoof_score=0.2, is_credential_harvester=False
        ),
        topology_forensics=TopologyForensics(
            graph_nodes_count=6, memae_reconstruction_loss=0.41, is_zero_day_route=False
        ),
        overall_risk=88,
        analyst_trace="Spoofed sender. VERDICT: PHISHING",
    )


def _header(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "arc": "none",
        "route_hop_count": 2,
        "private_ip_leak": False,
        "timestamp_regression_flag": False,
        "display_name_spoof_risk": 0.0,
    }
    return {**base, **overrides}


def test_json_decoded_payload_validates_with_model_validate() -> None:
    original = _assessment()

    decoded = json.loads(original.model_dump_json())

    assert ThreatAssessment.model_validate(decoded) == original
    assert ThreatAssessment.model_validate_json(original.model_dump_json()) == original


def test_auth_status_strings_are_exact() -> None:
    assert HeaderForensics.model_validate(_header()).spf is AuthStatus.PASS
    with pytest.raises(ValidationError, match="spf"):
        HeaderForensics.model_validate(_header(spf="softpass"))


@pytest.mark.parametrize(
    "override",
    [{"route_hop_count": "2"}, {"private_ip_leak": "false"}, {"display_name_spoof_risk": "0.5"}, {"extra": 1}],
)
def test_other_fields_stay_strict(override: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        HeaderForensics.model_validate(_header(**override))


def test_contracts_are_frozen() -> None:
    assessment = _assessment()

    with pytest.raises(ValidationError):
        assessment.overall_risk = 1  # type: ignore[misc]
