"""Ablation study: what each modality contributes to the fusion model.

    python scripts/run_ablation_study.py               # full research corpus -> models_research/ablation_results.md
    python scripts/run_ablation_study.py --limit 600   # quick look at the first 600 emails (classes alternate)

Each configuration removes a set of features and retrains the fusion forest on the
same stratified folds the trainer uses, scoring every email out of fold, so a row
measures what the model loses without that evidence. Zeroing columns at prediction
time instead would feed the deployed model inputs it never saw ("no link" and "no
private hop" are real values, not absences) and measure its reaction to them; and
the deployed model was trained on this very corpus, so scoring it here would be
in-sample. The MemAE column holds the trainer's cross-fitted losses, so removing it
is a real ablation rather than a no-op on zeros.
"""

import sys
from pathlib import Path
from typing import Final

import numpy as np
import numpy.typing as npt

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:  # `python scripts/run_ablation_study.py` from anywhere
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.train_orchestrator import (  # noqa: E402
    MEMAE_LOSS_COLUMN,
    cross_fitted_memae_losses,
    extract_features_concurrently,
    stratified_splits,
)
from src.core.config import get_settings  # noqa: E402
from src.fusion.meta_scorer import FEATURES, N_FEATURES  # noqa: E402
from src.topology.memae_model import GraphMemAE  # noqa: E402

RESEARCH_DIR: Final = PROJECT_ROOT / "data" / "raw" / "research"
MODERN_PHISHING_DIR: Final = PROJECT_ROOT / "data" / "raw" / "modern_2026"

Matrix = npt.NDArray[np.float64]
Labels = npt.NDArray[np.int64]

# Column indices per modality, derived from FEATURES so they cannot drift from the row
# layout: one entry per subsystem, plus GNN_ROUTING for the MemAE's own output (the
# TOPOLOGY_GNN subsystem also holds the graph's node count, which needs no network).
MODALITY_MAP: Final[dict[str, list[int]]] = {
    **{
        subsystem: [index for index, (_, owner) in enumerate(FEATURES) if owner == subsystem]
        for subsystem in dict.fromkeys(owner for _, owner in FEATURES)
    },
    "GNN_ROUTING": [MEMAE_LOSS_COLUMN],
}


def _matrix(rows: list[npt.NDArray[np.float64]]) -> Matrix:
    matrix: Matrix = np.vstack(rows) if rows else np.empty((0, N_FEATURES), dtype=np.float64)
    if matrix.shape[1] != N_FEATURES:
        raise ValueError(f"expected rows of {N_FEATURES} features, got shape {matrix.shape}")
    return matrix


def load_evaluation_subset(limit: int = 0, data_dir: Path = RESEARCH_DIR) -> tuple[Matrix, Labels]:
    """(X_base of shape [N, 12], y_true) for a labelled corpus, exactly as the trainer sees it.

    Rows come from the training extractors; the MemAE column is filled with the same
    cross-fitted losses the trainer computes (each from a MemAE that never trained on
    that email). ``limit`` > 0 keeps only the first emails (classes alternate).
    """
    rows, dags, labels = extract_features_concurrently(data_dir, limit)
    y_true = np.asarray(labels, dtype=np.int64)
    X_base = _matrix(rows)
    X_base[:, MEMAE_LOSS_COLUMN] = cross_fitted_memae_losses(dags, y_true, stratified_splits(y_true))
    if X_base.shape != (len(y_true), N_FEATURES):
        raise ValueError(f"expected [{len(y_true)}, {N_FEATURES}] features, got {list(X_base.shape)}")
    return X_base, y_true


def load_out_of_time_phishing(memae_path: Path | None = None, data_dir: Path = MODERN_PHISHING_DIR) -> Matrix:
    """[M, 12] rows for the unseen 2023-25 phishing, MemAE column scored by a trained MemAE.

    The deployed MemAE (the default) is the one a final training run fits on every
    benign research email, so these are the rows production would score.
    """
    memae_path = memae_path or get_settings().MODELS_DIR / "topology" / "memae.pt"
    if not memae_path.is_file():  # GraphMemAE would write a placeholder there instead
        raise FileNotFoundError(f"{memae_path} is missing; train and promote a MemAE first")
    memae = GraphMemAE(memae_path)
    if memae.is_placeholder:
        raise ValueError(f"{memae_path} is an untrained placeholder; its losses mean nothing")
    rows, dags, labels = extract_features_concurrently(data_dir)
    if any(label != 1 for label in labels):
        raise ValueError(f"{data_dir} must hold phishing only (a phishing/ or spam/ folder)")
    X_modern = _matrix(rows)
    X_modern[:, MEMAE_LOSS_COLUMN] = [memae.compute_anomaly_loss(dag) for dag in dags]
    return X_modern
