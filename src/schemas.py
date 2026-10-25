"""Immutable data contracts shared by every SOC analysis stage.

Every model is frozen, strict (no silent type coercion) and rejects unknown
fields, so a verdict cannot be mutated or smuggled extra keys after it leaves
the stage that produced it. JSON input (API / SIEM replay) may still use enum
values such as ``"pass"``; Python callers must pass real ``AuthStatus`` members.
"""

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

UnitScore = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
NonNegativeInt = Annotated[int, Field(ge=0)]
RiskScore = Annotated[int, Field(ge=0, le=100)]


class AuthStatus(StrEnum):
    """Authentication-Results method outcome (RFC 8601 result keywords)."""

    PASS = "pass"
    FAIL = "fail"
    NEUTRAL = "neutral"
    NONE = "none"
    PERMERROR = "permerror"
    TEMPERROR = "temperror"


class _Contract(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class HeaderForensics(_Contract):
    """Findings from the transport and authentication headers."""

    spf: Annotated[AuthStatus, Field(description="SPF result for the envelope sender.")]
    dkim: Annotated[AuthStatus, Field(description="DKIM signature verification result.")]
    dmarc: Annotated[AuthStatus, Field(description="DMARC alignment/policy result.")]
    arc: Annotated[AuthStatus, Field(description="ARC chain validation result.")]
    route_hop_count: Annotated[
        NonNegativeInt, Field(description="Number of Received hops in the delivery path.")
    ]
    private_ip_leak: Annotated[
        bool, Field(description="An RFC 1918 / loopback / link-local address appears in the route.")
    ]
    timestamp_regression_flag: Annotated[
        bool, Field(description="A later hop is timestamped before an earlier one.")
    ]
    display_name_spoof_risk: Annotated[
        UnitScore, Field(description="Likelihood the From display name impersonates another identity.")
    ]
    impersonated_brand: Annotated[
        str | None, Field(description="Brand named in the display name but not owning the From domain.")
    ] = None
    subject: Annotated[str | None, Field(description="Decoded Subject header.")] = None
    from_domain: Annotated[
        str | None, Field(description="Registered domain of the From address.")
    ] = None
    reply_to_domain: Annotated[
        str | None, Field(description="Registered domain of the Reply-To address.")
    ] = None
    return_path_domain: Annotated[
        str | None, Field(description="Registered domain of the Return-Path (envelope sender).")
    ] = None


class VisionForensics(_Contract):
    """Findings from rendering and visually classifying the landing page."""

    screenshot_hash: Annotated[
        str,
        Field(
            pattern=r"^[0-9a-f]{16,128}$",
            description="Lower-case hex digest (perceptual or cryptographic) of the rendered page.",
        ),
    ]
    visual_spoof_score: Annotated[
        UnitScore, Field(description="Visual similarity to a protected brand's genuine page.")
    ]
    detected_brand: Annotated[
        str | None,
        Field(min_length=1, max_length=128, description="Brand the page imitates, if any."),
    ] = None
    is_credential_harvester: Annotated[
        bool, Field(description="The page collects credentials or payment data.")
    ]


class TopologyForensics(_Contract):
    """Findings from the graph model over the message's delivery route."""

    graph_nodes_count: Annotated[
        NonNegativeInt, Field(description="Nodes in the route/infrastructure graph.")
    ]
    memae_reconstruction_loss: Annotated[
        float,
        Field(
            ge=0.0,
            allow_inf_nan=False,
            description="Memory-augmented autoencoder reconstruction loss; high means unfamiliar.",
        ),
    ]
    is_zero_day_route: Annotated[
        bool, Field(description="The loss exceeds the anomaly threshold for known routes.")
    ]


class ThreatAssessment(_Contract):
    """Final verdict for one message, aggregating every forensic stage."""

    header_forensics: HeaderForensics
    vision_forensics: Annotated[
        VisionForensics | None, Field(description="Absent when no landing page was rendered.")
    ] = None
    topology_forensics: Annotated[
        TopologyForensics | None, Field(description="Absent when the route graph was not scored.")
    ] = None
    overall_risk: Annotated[RiskScore, Field(description="Aggregate risk from 0 (benign) to 100.")]
    analyst_trace: Annotated[
        str, Field(min_length=1, description="Human-readable reasoning behind the verdict.")
    ]
