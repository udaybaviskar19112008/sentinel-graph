"""Late-fusion meta-scorer over every upstream tier's numeric output.

Each email becomes one strictly ordered 10-feature row (``FEATURES``); a tree
ensemble turns it into a phishing probability that ``xai_engine`` can attribute
feature by feature.

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

# (feature name, producing subsystem), in model column order. Never reorder: a trained
# model's columns are positional.
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
            self.model, self.is_dummy = self._load(self.model_path)
        else:
            logger.warning(
                "Fusion meta-model missing; fitting a placeholder on synthetic data",
                extra={"event": "fusion.placeholder_generated", "model_path": self.model_path},
            )
            self.model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
            self.model.fit(*_synthetic_training_set(np.random.default_rng(42)))
            self.is_dummy = True
            self.save(self.model_path, dummy=True)
        if self.is_dummy:
            logger.warning(
                "Fusion meta-model is a synthetic placeholder; risk scores carry no meaning",
                extra={"event": "fusion.placeholder_model", "model_path": self.model_path},
            )
        self._phishing_column = list(self.model.classes_).index(1)

    def save(self, path: Path, *, dummy: bool = False) -> None:
        self.write_bundle(self.model, path, dummy=dummy)

    @staticmethod
    def write_bundle(model: Any, path: Path, *, dummy: bool) -> None:
        """Write a fitted classifier with its feature contract, atomically (temp file + rename)."""
        bundle = {"format": MODEL_FORMAT, "dummy": dummy, "feature_names": FEATURE_NAMES, "model": model}
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}-", suffix=".joblib")
        os.close(handle)
        try:
            joblib.dump(bundle, temp_name)
            os.replace(temp_name, path)
        finally:
            Path(temp_name).unlink(missing_ok=True)

    @staticmethod
    def _load(path: Path) -> tuple[Any, bool]:
        bundle = joblib.load(path)
        if not isinstance(bundle, dict) or bundle.get("format") != MODEL_FORMAT:
            raise ValueError(f"{path} is not a {MODEL_FORMAT} bundle")
        if tuple(bundle.get("feature_names", ())) != FEATURE_NAMES:
            raise ValueError(f"{path} was trained on features {bundle.get('feature_names')}, not {FEATURE_NAMES}")
        model = bundle["model"]
        if getattr(model, "n_features_in_", None) != N_FEATURES or 1 not in getattr(model, "classes_", ()):
            raise ValueError(f"{path} holds a model that does not take {N_FEATURES} features or predict class 1")
        return model, bool(bundle.get("dummy", False))

    @staticmethod
    def _build_feature_vector(
        headers: Mapping[str, Any],
        vision: Mapping[str, Any],
        topology: Mapping[str, Any],
        slm_verdict: str,
    ) -> npt.NDArray[np.float64]:
        """One model row, shape (1, 10), in ``FEATURES`` order.

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
            ],
            dtype=np.float64,
        )
        return np.nan_to_num(row, nan=0.0, posinf=1.0, neginf=0.0).reshape(1, N_FEATURES)

    def predict_risk(self, feature_vector: npt.NDArray[np.float64]) -> float:
        """Probability that the email is phishing (class 1), for one 10-feature row."""
        row = np.asarray(feature_vector, dtype=np.float64)
        if row.size != N_FEATURES:
            raise ValueError(f"expected {N_FEATURES} features, got shape {row.shape}")
        row = np.nan_to_num(row.reshape(1, N_FEATURES), nan=0.0, posinf=1.0, neginf=0.0)
        return float(self.model.predict_proba(row)[0, self._phishing_column])
