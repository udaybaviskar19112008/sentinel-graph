"""Late-fusion meta-scorer over every upstream tier's numeric output.

Each email becomes one strictly ordered 12-feature row (``FEATURES``); a tree
ensemble turns it into a phishing probability that ``xai_engine`` can attribute
feature by feature.

A saved model names the features it was trained on, and scoring hands it exactly
those columns, by name. A model trained before a feature existed therefore keeps
scoring exactly as it did (the newer feature is ignored, and logged, until a model
trained on it is promoted); a model naming a feature this code does not produce is
refused.

The model lives at ``MODELS_DIR/fusion_meta.joblib``. joblib files are pickles,
so loading one runs code: that directory must be as trusted as the source tree.
When the file is missing, a forest fitted on synthetic rows is written instead;
its scores carry no meaning and ``is_dummy`` stays true until a trained model lands.
"""

import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
import numpy.typing as npt
from sklearn.ensemble import RandomForestClassifier

from src.core.config import get_settings
from src.core.logger import get_logger
from src.schemas import VerdictLevel

logger = get_logger(__name__)

# (feature name, producing subsystem), in row order. Append; never reorder or rename:
# saved models address their columns by these names.
FEATURES: Final[tuple[tuple[str, str], ...]] = (
    ("auth_fail_count", "PROTOCOL_FORENSICS"),
    ("display_name_spoof_risk", "PROTOCOL_FORENSICS"),
    ("private_ip_leak", "PROTOCOL_FORENSICS"),
    ("timestamp_regression", "PROTOCOL_FORENSICS"),
    ("screenshot_hash_exists", "VISION_ENGINE"),
    ("visual_spoof_score", "VISION_ENGINE"),
    ("is_cred_harvester", "VISION_ENGINE"),
    ("graph_nodes_count", "TOPOLOGY_GNN"),
    ("memae_loss", "TOPOLOGY_GNN"),
    ("slm_verdict_severity", "COGNITIVE_SLM"),
    # Lexical evidence about the message's links and text, not about any delivery hop.
    ("dga_max_entropy", "CONTENT_HEURISTICS"),
    ("nlp_urgency_score", "CONTENT_HEURISTICS"),
)
FEATURE_NAMES: Final = tuple(name for name, _ in FEATURES)
N_FEATURES: Final = len(FEATURES)

MODEL_FORMAT: Final = "soc-fusion-meta/1"
_AUTH_METHODS: Final = ("spf", "dkim", "dmarc", "arc")
_SEVERITY: Final = {verdict.value: rank for rank, verdict in enumerate(VerdictLevel)}


def _number(value: Any) -> float:
    """float(value), or NaN for None and anything non-numeric (nan_to_num zeroes it later)."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def as_feature_row(feature_vector: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    """``feature_vector`` as one finite (1, N_FEATURES) row; ValueError for any other width.

    NaN becomes 0 and -inf 0, but +inf becomes 1: an unboundedly anomalous MemAE loss
    must not read as a perfectly normal one.
    """
    row = np.asarray(feature_vector, dtype=np.float64)
    if row.size != N_FEATURES:
        raise ValueError(f"expected {N_FEATURES} features, got shape {row.shape}")
    return np.nan_to_num(row.reshape(1, N_FEATURES), nan=0.0, posinf=1.0, neginf=0.0)


def _synthetic_training_set(rng: np.random.Generator) -> tuple[npt.NDArray[np.float64], npt.NDArray[np.int64]]:
    """50 benign and 50 phishing rows with overlapping, plausible feature ranges."""

    def rows(phishing: bool) -> npt.NDArray[np.float64]:
        n = 50
        p = 0.75 if phishing else 0.1  # chance a binary indicator fires
        return np.column_stack(
            [
                rng.integers(1, 4, n) if phishing else rng.integers(0, 2, n),  # auth_fail_count
                rng.binomial(1, p, n).astype(float),  # display_name_spoof_risk
                rng.binomial(1, p * 0.5, n),  # private_ip_leak
                rng.binomial(1, p * 0.5, n),  # timestamp_regression
                rng.binomial(1, 0.9 if phishing else 0.5, n),  # screenshot_hash_exists
                rng.uniform(0.5, 1.0, n) if phishing else rng.uniform(0.0, 0.4, n),  # visual_spoof_score
                rng.binomial(1, p, n),  # is_cred_harvester
                rng.integers(4, 14, n) if phishing else rng.integers(3, 9, n),  # graph_nodes_count
                rng.uniform(0.7, 1.5, n) if phishing else rng.uniform(0.3, 0.8, n),  # memae_loss
                rng.integers(2, 4, n) if phishing else rng.integers(0, 2, n),  # slm_verdict_severity
                rng.uniform(2.8, 4.2, n) if phishing else rng.uniform(1.5, 3.4, n),  # dga_max_entropy
                rng.choice([0.0, 0.25, 0.5, 1.0], n) if phishing else rng.choice([0.0, 0.25], n, p=[0.9, 0.1]),  # nlp
            ]
        ).astype(np.float64)

    features = np.vstack([rows(phishing=False), rows(phishing=True)])
    labels = np.repeat(np.array([0, 1], dtype=np.int64), 50)
    return features, labels


class FusionMetaModel:
    """Feature assembly plus the fitted meta-classifier (class 1 = phishing)."""

    def __init__(self, model_path: Path | None = None) -> None:
        self.model_path = model_path or get_settings().MODELS_DIR / "fusion_meta.joblib"
        if self.model_path.exists():
            self.model, self.is_dummy, self.feature_names = self._load(self.model_path)
        else:
            logger.warning(
                "Fusion meta-model missing; fitting a placeholder on synthetic data",
                extra={"event": "fusion.placeholder_generated", "model_path": self.model_path},
            )
            self.model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
            self.model.fit(*_synthetic_training_set(np.random.default_rng(42)))
            self.is_dummy, self.feature_names = True, FEATURE_NAMES
            self.save(self.model_path, dummy=True)
        if self.is_dummy:
            logger.warning(
                "Fusion meta-model is a synthetic placeholder; risk scores carry no meaning",
                extra={"event": "fusion.placeholder_model", "model_path": self.model_path},
            )
        # Which columns of a full FEATURES row this model takes, in its own training order.
        self.columns = np.array([FEATURE_NAMES.index(name) for name in self.feature_names], dtype=np.intp)
        self.ignored_features = tuple(name for name in FEATURE_NAMES if name not in self.feature_names)
        if self.ignored_features:
            logger.warning(
                "Fusion meta-model predates some features; they are ignored until a model trained on them is promoted",
                extra={
                    "event": "fusion.features_ignored",
                    "model_path": self.model_path,
                    "ignored_features": list(self.ignored_features),
                },
            )
        self._phishing_column = list(self.model.classes_).index(1)

    def save(self, path: Path, *, dummy: bool = False) -> None:
        self.write_bundle(self.model, path, dummy=dummy, feature_names=self.feature_names)

    @staticmethod
    def write_bundle(
        model: Any, path: Path, *, dummy: bool, feature_names: tuple[str, ...] = FEATURE_NAMES
    ) -> None:
        """Write a fitted classifier with its feature contract, atomically (temp file + rename)."""
        bundle = {"format": MODEL_FORMAT, "dummy": dummy, "feature_names": tuple(feature_names), "model": model}
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}-", suffix=".joblib")
        os.close(handle)
        try:
            joblib.dump(bundle, temp_name)
            os.replace(temp_name, path)
        finally:
            Path(temp_name).unlink(missing_ok=True)

    @staticmethod
    def _load(path: Path) -> tuple[Any, bool, tuple[str, ...]]:
        bundle = joblib.load(path)
        if not isinstance(bundle, dict) or bundle.get("format") != MODEL_FORMAT:
            raise ValueError(f"{path} is not a {MODEL_FORMAT} bundle")
        names = tuple(str(name) for name in bundle.get("feature_names", ()))
        if not names or len(set(names)) != len(names) or not set(names) <= set(FEATURE_NAMES):
            raise ValueError(f"{path} was trained on features {list(names)}; this code produces {list(FEATURE_NAMES)}")
        model = bundle["model"]
        if getattr(model, "n_features_in_", None) != len(names) or 1 not in getattr(model, "classes_", ()):
            raise ValueError(f"{path} holds a model that does not take its {len(names)} named features or predict class 1")
        return model, bool(bundle.get("dummy", False)), names

    @staticmethod
    def _build_feature_vector(
        headers: Mapping[str, Any],
        vision: Mapping[str, Any],
        topology: Mapping[str, Any],
        slm_verdict: str,
    ) -> npt.NDArray[np.float64]:
        """One full row, shape (1, N_FEATURES), in ``FEATURES`` order.

        Inputs are the ``model_dump()`` of ``HeaderForensics``, ``VisionForensics`` and
        ``TopologyForensics`` (an empty mapping when a tier did not run). Missing or
        non-numeric values become 0; an unknown verdict counts as SUSPICIOUS, matching
        the verdict extractor's fallback.
        """
        auth_failures = sum(str(headers.get(method, "")).lower() == "fail" for method in _AUTH_METHODS)
        verdict = str(slm_verdict).strip().upper()
        row = np.array(
            [
                auth_failures,
                _number(headers.get("display_name_spoof_risk")),
                _number(headers.get("private_ip_leak")),
                _number(headers.get("timestamp_regression_flag")),
                1.0 if vision.get("screenshot_hash") else 0.0,
                _number(vision.get("visual_spoof_score")),
                _number(vision.get("is_credential_harvester")),
                _number(topology.get("graph_nodes_count")),
                _number(topology.get("memae_reconstruction_loss")),
                _SEVERITY.get(verdict, _SEVERITY[VerdictLevel.SUSPICIOUS]),
                _number(headers.get("dga_max_entropy")),
                _number(headers.get("nlp_urgency_score")),
            ],
            dtype=np.float64,
        )
        return as_feature_row(row)

    def predict_risk(self, feature_vector: npt.NDArray[np.float64]) -> float:
        """Probability that the email is phishing (class 1), for one full ``FEATURES`` row."""
        row = as_feature_row(feature_vector)[:, self.columns]
        return float(self.model.predict_proba(row)[0, self._phishing_column])
