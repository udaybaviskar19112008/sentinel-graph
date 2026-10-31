import hashlib
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pytest
import shap

from sklearn.ensemble import RandomForestClassifier

from src.fusion.meta_scorer import (
    FEATURE_NAMES,
    FEATURES,
    MODEL_FORMAT,
    N_FEATURES,
    FusionMetaModel,
    _synthetic_training_set,
)
from src.fusion.xai_engine import MIN_PERCENTAGE, explain_positive_class, extract_shap_contributions
from src.schemas import AuthStatus, HeaderForensics, TopologyForensics, VisionForensics

build = FusionMetaModel._build_feature_vector


def _headers(*, hostile: bool) -> dict[str, Any]:
    status = AuthStatus.FAIL if hostile else AuthStatus.PASS
    return HeaderForensics(
        spf=status,
        dkim=AuthStatus.NONE if hostile else AuthStatus.PASS,
        dmarc=status,
        arc=AuthStatus.NONE,
        route_hop_count=4,
        private_ip_leak=hostile,
        timestamp_regression_flag=hostile,
        display_name_spoof_risk=1.0 if hostile else 0.0,
        impersonated_brand="paypal" if hostile else None,
        dga_max_entropy=3.8 if hostile else 2.1,
        nlp_urgency_score=0.75 if hostile else 0.0,
    ).model_dump()


def _vision(*, hostile: bool) -> dict[str, Any]:
    return VisionForensics(
        screenshot_hash=hashlib.sha256(b"png").hexdigest(),
        visual_spoof_score=0.92 if hostile else 0.05,
        detected_brand="paypal" if hostile else None,
        is_credential_harvester=hostile,
    ).model_dump()


def _topology(*, hostile: bool) -> dict[str, Any]:
    return TopologyForensics(
        graph_nodes_count=9 if hostile else 5,
        memae_reconstruction_loss=1.21 if hostile else 0.42,
        is_zero_day_route=hostile,
    ).model_dump()


@pytest.fixture
def model_path(tmp_path: Path) -> Path:
    return tmp_path / "fusion_meta.joblib"


@pytest.fixture
def meta(model_path: Path) -> FusionMetaModel:
    return FusionMetaModel(model_path)


@pytest.fixture
def hostile_row() -> np.ndarray:
    return build(_headers(hostile=True), _vision(hostile=True), _topology(hostile=True), "CRITICAL")


# --- Stage 6A: features and meta-model -----------------------------------------


def test_highly_suspicious_email_scores_above_half(meta: FusionMetaModel, hostile_row: np.ndarray) -> None:
    assert hostile_row.shape == (1, 12)
    assert hostile_row.tolist() == [[2, 1.0, 1, 1, 1, 0.92, 1, 9, 1.21, 3, 3.8, 0.75]]

    risk = meta.predict_risk(hostile_row)

    assert isinstance(risk, float)
    assert risk > 0.5


def test_benign_email_scores_below_half(meta: FusionMetaModel) -> None:
    row = build(_headers(hostile=False), _vision(hostile=False), _topology(hostile=False), "BENIGN")

    assert meta.predict_risk(row) < 0.5


@pytest.mark.parametrize(
    ("verdict", "severity"),
    [("BENIGN", 0), ("SUSPICIOUS", 1), ("PHISHING", 2), ("CRITICAL", 3), (" phishing ", 2), ("MALICIOUS", 1), ("", 1)],
)
def test_verdict_maps_to_severity(verdict: str, severity: int) -> None:
    assert build({}, {}, {}, verdict)[0, 9] == severity


def test_missing_tiers_and_non_finite_values_are_neutralised() -> None:
    row = build(
        {"spf": "fail", "dkim": "FAIL", "display_name_spoof_risk": None, "private_ip_leak": "yes"},
        {},  # vision never ran: no screenshot
        {"graph_nodes_count": float("-inf"), "memae_reconstruction_loss": float("inf")},
        "BENIGN",
    )

    assert row.tolist() == [[2, 0, 0, 0, 0, 0, 0, 0, 1.0, 0, 0, 0]]
    assert np.isfinite(row).all()


def test_predict_risk_accepts_flat_rows_and_rejects_wrong_widths(meta: FusionMetaModel, hostile_row: np.ndarray) -> None:
    assert meta.predict_risk(hostile_row.ravel()) == meta.predict_risk(hostile_row)
    with pytest.raises(ValueError, match="expected 12 features"):
        meta.predict_risk(np.zeros(10))  # the old width is a different contract now


def test_placeholder_is_saved_and_reloaded_identically(
    meta: FusionMetaModel, model_path: Path, hostile_row: np.ndarray
) -> None:
    assert meta.is_dummy
    assert model_path.is_file()
    assert sorted(p.name for p in model_path.parent.iterdir()) == ["fusion_meta.joblib"]
    before = model_path.stat().st_mtime_ns

    reloaded = FusionMetaModel(model_path)

    assert model_path.stat().st_mtime_ns == before
    assert reloaded.is_dummy
    assert reloaded.predict_risk(hostile_row) == meta.predict_risk(hostile_row)


def test_trained_bundle_is_not_reported_as_dummy(meta: FusionMetaModel, tmp_path: Path) -> None:
    path = tmp_path / "trained.joblib"
    meta.save(path, dummy=False)

    assert FusionMetaModel(path).is_dummy is False


@pytest.mark.parametrize(
    ("bundle", "message"),
    [
        pytest.param(lambda m: m.model, "not a soc-fusion-meta", id="bare-estimator"),
        pytest.param(
            lambda m: {"format": MODEL_FORMAT, "feature_names": (*FEATURE_NAMES[:-1], "future_feature"), "model": m.model},
            "was trained on features",
            id="unknown-feature",
        ),
        pytest.param(
            lambda m: {"format": MODEL_FORMAT, "feature_names": (*FEATURE_NAMES[:-1], FEATURE_NAMES[0]), "model": m.model},
            "was trained on features",
            id="duplicate-feature",
        ),
        pytest.param(
            lambda m: {"format": MODEL_FORMAT, "feature_names": FEATURE_NAMES[:10], "model": m.model},
            "does not take its 10 named features",
            id="names-and-model-disagree",
        ),
    ],
)
def test_incompatible_model_files_are_rejected(
    meta: FusionMetaModel, tmp_path: Path, bundle: Any, message: str
) -> None:
    path = tmp_path / "other.joblib"
    joblib.dump(bundle(meta), path)

    with pytest.raises(ValueError, match=message):
        FusionMetaModel(path)


# --- Stage 6B: SHAP attribution ----------------------------------------------


def test_shap_percentages_sum_to_about_100(meta: FusionMetaModel, hostile_row: np.ndarray) -> None:
    contributions = extract_shap_contributions(meta.model, hostile_row)

    total = sum(c["percentage"] for c in contributions)
    dropped = len(FEATURES) - len(contributions)
    # Every dropped feature took under 1%, so at most `dropped` percent is missing.
    assert total == pytest.approx(100.0, abs=max(dropped * MIN_PERCENTAGE, 1e-9))
    assert total <= 100.0 + 1e-9
    assert contributions and all(c["percentage"] >= MIN_PERCENTAGE for c in contributions)
    percentages = [c["percentage"] for c in contributions]
    assert percentages == sorted(percentages, reverse=True)
    subsystems = dict(FEATURES)
    for contribution in contributions:
        assert set(contribution) == {"feature_name", "impact", "percentage", "subsystem"}
        assert contribution["subsystem"] == subsystems[contribution["feature_name"]]


def test_shap_values_add_up_to_the_predicted_risk(meta: FusionMetaModel, hostile_row: np.ndarray) -> None:
    base_value, impacts = explain_positive_class(meta, hostile_row)

    assert impacts.shape == (N_FEATURES,)
    assert base_value + impacts.sum() == pytest.approx(meta.predict_risk(hostile_row), abs=1e-6)
    assert impacts.sum() > 0  # this email is pushed toward phishing


class _FakeExplainer:
    """Stands in for shap.TreeExplainer with a fixed output layout."""

    shap_output: Any = None
    expected_value: Any = None

    def __init__(self, model: Any) -> None:
        pass

    def shap_values(self, row: np.ndarray) -> Any:
        return self.shap_output


_POSITIVE = np.array([[0.30, 0.10, 0.0, 0.0, 0.0, 0.05, 0.0, 0.0, -0.05, 0.004, 0.0, 0.0]])


@pytest.mark.parametrize(
    ("shap_output", "expected_value"),
    [
        pytest.param([-_POSITIVE, _POSITIVE], [0.6, 0.4], id="legacy-list-per-class"),
        pytest.param(np.stack([-_POSITIVE, _POSITIVE], axis=-1), np.array([0.6, 0.4]), id="3d-array"),
        pytest.param(_POSITIVE, 0.4, id="single-output"),
    ],
)
def test_every_shap_output_layout_selects_the_phishing_class(
    meta: FusionMetaModel, monkeypatch: pytest.MonkeyPatch, shap_output: Any, expected_value: Any
) -> None:
    explainer = type("Explainer", (_FakeExplainer,), {"shap_output": shap_output, "expected_value": expected_value})
    monkeypatch.setattr(shap, "TreeExplainer", explainer)

    base_value, impacts = explain_positive_class(meta.model, np.zeros(N_FEATURES))
    contributions = extract_shap_contributions(meta.model, np.zeros(N_FEATURES))

    assert base_value == pytest.approx(0.4)
    np.testing.assert_allclose(impacts, _POSITIVE[0])
    assert [(c["feature_name"], round(c["percentage"], 1)) for c in contributions] == [
        ("auth_fail_count", 59.5),
        ("display_name_spoof_risk", 19.8),
        ("visual_spoof_score", 9.9),
        ("memae_loss", 9.9),
    ]  # slm_verdict_severity (0.8%) falls under the 1% floor
    assert contributions[-1]["impact"] < 0


def test_zero_attribution_returns_empty_list(meta: FusionMetaModel, monkeypatch: pytest.MonkeyPatch) -> None:
    explainer = type("Explainer", (_FakeExplainer,), {"shap_output": np.zeros((1, N_FEATURES, 2)), "expected_value": [0.5, 0.5]})
    monkeypatch.setattr(shap, "TreeExplainer", explainer)

    assert extract_shap_contributions(meta, np.zeros(N_FEATURES)) == []


# --- 12-feature contract -------------------------------------------------------


def test_meta_scorer_12d(meta: FusionMetaModel) -> None:
    assert N_FEATURES == 12
    assert meta.feature_names == FEATURE_NAMES and meta.ignored_features == ()
    assert meta.model.n_features_in_ == 12

    risk = meta.predict_risk(np.random.default_rng(0).random(12))

    assert isinstance(risk, float) and 0.0 <= risk <= 1.0  # a probability; the pipeline scales it to 0-100


def _legacy_ten_feature_model(path: Path) -> RandomForestClassifier:
    """A model saved before the content heuristics existed: trained on the first ten features."""
    features, labels = _synthetic_training_set(np.random.default_rng(7))
    model = RandomForestClassifier(n_estimators=20, max_depth=4, random_state=0).fit(features[:, :10], labels)
    FusionMetaModel.write_bundle(model, path, dummy=False, feature_names=FEATURE_NAMES[:10])
    return model


def test_model_trained_before_the_new_features_scores_exactly_as_before(
    tmp_path: Path, hostile_row: np.ndarray
) -> None:
    path = tmp_path / "legacy.joblib"
    legacy = _legacy_ten_feature_model(path)

    meta = FusionMetaModel(path)

    assert meta.ignored_features == ("dga_max_entropy", "nlp_urgency_score")
    expected = legacy.predict_proba(hostile_row[:, :10])[0, 1]
    assert meta.predict_risk(hostile_row) == expected
    changed = hostile_row.copy()
    changed[0, 10:] = [0.0, 0.0]
    assert meta.predict_risk(changed) == expected  # the new columns cannot move its score


def test_shap_gives_ignored_features_exactly_zero(tmp_path: Path, hostile_row: np.ndarray) -> None:
    path = tmp_path / "legacy.joblib"
    _legacy_ten_feature_model(path)
    meta = FusionMetaModel(path)

    base_value, impacts = explain_positive_class(meta, hostile_row)

    assert impacts.shape == (N_FEATURES,)
    assert impacts[10:].tolist() == [0.0, 0.0]
    assert base_value + impacts.sum() == pytest.approx(meta.predict_risk(hostile_row), abs=1e-6)
    named = {c["feature_name"] for c in extract_shap_contributions(meta, hostile_row)}
    assert named.isdisjoint(meta.ignored_features)


def test_columns_are_matched_by_name_not_position(tmp_path: Path, hostile_row: np.ndarray) -> None:
    # A bundle may list its features in any order; scoring must follow the names.
    order = np.random.default_rng(3).permutation(N_FEATURES)
    features, labels = _synthetic_training_set(np.random.default_rng(42))
    model = RandomForestClassifier(n_estimators=20, max_depth=4, random_state=0).fit(features[:, order], labels)
    path = tmp_path / "permuted.joblib"
    FusionMetaModel.write_bundle(model, path, dummy=False, feature_names=tuple(FEATURE_NAMES[i] for i in order))

    permuted = FusionMetaModel(path)

    assert permuted.ignored_features == ()
    assert permuted.predict_risk(hostile_row) == model.predict_proba(hostile_row[:, order])[0, 1]


def test_resaving_a_legacy_model_keeps_its_own_feature_list(tmp_path: Path) -> None:
    path, copy = tmp_path / "legacy.joblib", tmp_path / "copy.joblib"
    _legacy_ten_feature_model(path)

    FusionMetaModel(path).save(copy)

    assert FusionMetaModel(copy).feature_names == FEATURE_NAMES[:10]
