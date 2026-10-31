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

import argparse
import logging
import sys
from pathlib import Path
from typing import Final, TypedDict

import numpy as np
import numpy.typing as npt
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:  # `python scripts/run_ablation_study.py` from anywhere
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.train_orchestrator import (  # noqa: E402
    MEMAE_LOSS_COLUMN,
    cross_fitted_memae_losses,
    extract_features_concurrently,
    make_forest,
    out_of_fold_probabilities,
    stratified_splits,
)
from src.core.config import get_settings  # noqa: E402
from src.core.logger import configure_logging, shutdown_logging  # noqa: E402
from src.fusion.meta_scorer import FEATURE_NAMES, FEATURES, N_FEATURES  # noqa: E402
from src.topology.memae_model import GraphMemAE  # noqa: E402

RESEARCH_DIR: Final = PROJECT_ROOT / "data" / "raw" / "research"
MODERN_PHISHING_DIR: Final = PROJECT_ROOT / "data" / "raw" / "modern_2026"
RESULTS_PATH: Final = PROJECT_ROOT / "models_research" / "ablation_results.md"
THRESHOLD: Final = 0.5  # the runtime's decision threshold

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


def _columns(*names: str) -> list[int]:
    return [FEATURE_NAMES.index(name) for name in names]


# Configuration -> feature columns removed. "No content heuristics" *is* the legacy
# 10-feature model (both remove columns 10 and 11), so it appears once. Vision and the
# SLM are not ablated: they were constant in training, so removing them changes nothing.
ABLATIONS: Final[dict[str, list[int]]] = {
    "Baseline (all 12 features)": [],
    "No content heuristics (DGA + NLP) = legacy 10-feature": MODALITY_MAP["CONTENT_HEURISTICS"],
    "No DGA entropy": _columns("dga_max_entropy"),
    "No NLP coercion": _columns("nlp_urgency_score"),
    "No GNN routing (MemAE loss)": MODALITY_MAP["GNN_ROUTING"],
    "No topology (MemAE loss + graph size)": MODALITY_MAP["TOPOLOGY_GNN"],
    "No protocol forensics": MODALITY_MAP["PROTOCOL_FORENSICS"],
}


class AblationResult(TypedDict):
    roc_auc: float
    f1_score: float
    precision: float
    recall: float
    out_of_time_recall: float | None  # share of the unseen phishing caught at THRESHOLD


def evaluate_ablation(
    X_base: Matrix, y_true: Labels, removed_indices: list[int], X_out_of_time: Matrix | None = None
) -> AblationResult:
    """Retrain without ``removed_indices`` on the trainer's folds; score every email out of fold.

    ``X_base`` is never modified (column selection copies). With ``X_out_of_time``
    (phishing only), a forest fitted on every row also reports how many it catches.
    """
    removed = set(removed_indices)
    if not removed <= set(range(N_FEATURES)):
        raise ValueError(f"feature indices must lie in [0, {N_FEATURES}); got {sorted(removed)}")
    keep = [index for index in range(N_FEATURES) if index not in removed]
    if not keep:
        raise ValueError("an ablation must keep at least one feature")
    X_ablated = X_base[:, keep]

    oof = out_of_fold_probabilities(X_ablated, y_true, stratified_splits(y_true))
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, (oof >= THRESHOLD).astype(int), average="binary", pos_label=1, zero_division=0
    )
    caught: float | None = None
    if X_out_of_time is not None:
        forest = make_forest().fit(X_ablated, y_true)
        scores = forest.predict_proba(X_out_of_time[:, keep])[:, list(forest.classes_).index(1)]
        caught = float(np.mean(scores >= THRESHOLD))
    return AblationResult(
        roc_auc=float(roc_auc_score(y_true, oof)),
        f1_score=float(f1),
        precision=float(precision),
        recall=float(recall),
        out_of_time_recall=caught,
    )


def format_markdown(results: dict[str, AblationResult], y_true: Labels, out_of_time_count: int | None) -> str:
    """The results as a Markdown table, the first configuration being the baseline."""
    baseline = next(iter(results.values()))["roc_auc"]
    benign, phishing = np.bincount(y_true, minlength=2).tolist()
    lines = [
        "# Ablation study: fusion model",
        "",
        f"Research corpus: {len(y_true)} emails ({benign} legitimate, {phishing} phishing). Every row retrains the",
        "fusion forest without the listed features on the trainer's 5 stratified folds (identical for every row)",
        "and scores each email out of fold; the MemAE column holds cross-fitted losses.",
        "",
    ]
    header = "| Configuration | Features removed | OOF ROC-AUC | F1 @ 0.5 | AUC degradation |"
    rule = "|---|---|---|---|---|"
    if out_of_time_count is not None:
        header += f" 2023–25 phishing caught (n={out_of_time_count}) |"
        rule += "---|"
    lines += [header, rule]
    for label, result in results.items():
        removed = ", ".join(f"`{FEATURE_NAMES[index]}`" for index in ABLATIONS.get(label, [])) or "—"
        drop = (baseline - result["roc_auc"]) / baseline * 100
        degradation = "—" if label == next(iter(results)) else f"{drop:.2f}%"
        row = f"| {label} | {removed} | {result['roc_auc']:.3f} | {result['f1_score']:.3f} | {degradation} |"
        if out_of_time_count is not None:
            row += f" {result['out_of_time_recall']:.1%} |"
        lines.append(row)
    lines += [
        "",
        "AUC degradation = (baseline AUC − AUC) / baseline AUC; negative means the model did better without",
        "those features. F1 is for the phishing class at threshold 0.5. The out-of-time column fits a forest",
        "on every research email and applies it to unseen Nazario phishing from 2023–25, MemAE losses from the",
        "deployed MemAE. Vision and SLM features are not ablated: constant in training, they change nothing.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Drop-column ablation of the fusion model's modalities.")
    parser.add_argument("--limit", type=int, default=0, help="only the first N emails (classes alternate); 0 = all")
    parser.add_argument("--data-dir", type=Path, default=RESEARCH_DIR)
    parser.add_argument("--out", type=Path, default=RESULTS_PATH, help="Markdown table destination")
    parser.add_argument("--no-out-of-time", action="store_true", help="skip the unseen 2023-25 phishing column")
    args = parser.parse_args(argv)
    if args.limit < 0:
        parser.error("--limit must be >= 0")

    configure_logging(level=logging.WARNING)
    try:
        X_base, y_true = load_evaluation_subset(args.limit, args.data_dir)
        X_modern = None if args.no_out_of_time else load_out_of_time_phishing()
        results = {label: evaluate_ablation(X_base, y_true, removed, X_modern) for label, removed in ABLATIONS.items()}
    finally:
        shutdown_logging()
    table = format_markdown(results, y_true, None if X_modern is None else len(X_modern))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(table, encoding="utf-8")
    print(table)
    print(f"Written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
