"""Exact SHAP attribution of a fusion risk score to its features and subsystems.

For tree ensembles ``shap.TreeExplainer`` is exact, and additive: the base value
(the model's average output) plus every feature's SHAP value equals the
predicted phishing probability for this email.
"""

from typing import Any, Final, TypedDict

import numpy as np
import numpy.typing as npt
import shap

from src.core.logger import get_logger
from src.fusion.meta_scorer import FEATURES, N_FEATURES, FusionMetaModel, as_feature_row

logger = get_logger(__name__)

MIN_PERCENTAGE: Final = 1.0


class Contribution(TypedDict):
    feature_name: str
    impact: float  # signed SHAP value: positive pushes toward phishing
    percentage: float  # share of the total absolute SHAP mass, 0-100
    subsystem: str


def _positive_class(values: Any, class_index: int, width: int) -> npt.NDArray[np.float64]:
    """This row's ``width`` SHAP values for the phishing class, whichever layout this shap version returns."""
    if isinstance(values, list):  # shap < 0.45: one (rows, features) array per class
        values = values[min(class_index, len(values) - 1)]
    array: npt.NDArray[np.float64] = np.asarray(values, dtype=np.float64)
    if array.ndim == 3:  # shap >= 0.45: (rows, features, classes)
        array = array[..., min(class_index, array.shape[-1] - 1)]
    # Two dimensions now; a single-output model was already explaining the positive class.
    row: npt.NDArray[np.float64] = array.reshape(-1, width)[0]
    return row


def explain_positive_class(
    meta_model: Any, feature_vector: npt.NDArray[np.float64]
) -> tuple[float, npt.NDArray[np.float64]]:
    """(base value, SHAP values in ``FEATURES`` order) for the phishing class of one full row.

    ``meta_model`` is a ``FusionMetaModel`` or a fitted tree classifier over all of
    ``FEATURES``. A feature the model was not trained on gets an impact of exactly 0.
    """
    if isinstance(meta_model, FusionMetaModel):
        estimator, columns = meta_model.model, meta_model.columns
    else:
        estimator, columns = meta_model, np.arange(N_FEATURES)
    row = as_feature_row(feature_vector)[:, columns]

    class_index = list(estimator.classes_).index(1)
    explainer = shap.TreeExplainer(estimator)
    impacts = np.zeros(N_FEATURES, dtype=np.float64)
    impacts[columns] = _positive_class(explainer.shap_values(row), class_index, len(columns))
    expected = np.atleast_1d(np.asarray(explainer.expected_value, dtype=np.float64))
    base_value = float(expected[min(class_index, expected.size - 1)])
    return base_value, impacts


def extract_shap_contributions(meta_model: Any, feature_vector: npt.NDArray[np.float64]) -> list[Contribution]:
    """Features ranked by their share of the decision, largest first.

    Features under 1% are dropped, so the listed percentages sum to just under 100
    (each omitted feature took less than 1%). An all-zero attribution returns [].
    """
    base_value, impacts = explain_positive_class(meta_model, feature_vector)
    total = float(np.abs(impacts).sum())
    if total == 0.0:
        return []
    contributions = [
        Contribution(
            feature_name=name,
            impact=float(impact),
            percentage=abs(float(impact)) / total * 100.0,
            subsystem=subsystem,
        )
        for (name, subsystem), impact in zip(FEATURES, impacts, strict=True)
    ]
    ranked = sorted(
        (c for c in contributions if c["percentage"] >= MIN_PERCENTAGE),
        key=lambda c: c["percentage"],
        reverse=True,
    )
    logger.info(
        "SHAP attribution computed",
        extra={
            "event": "fusion.shap_attribution",
            "base_value": base_value,
            "explained_risk": base_value + float(impacts.sum()),
            "top_features": [c["feature_name"] for c in ranked[:3]],
        },
    )
    return ranked
