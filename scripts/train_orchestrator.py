"""Offline training for the topology MemAE and the late-fusion meta-model.

    python scripts/train_orchestrator.py --debug-slice 100            # data/raw/modern_2026

Stage 7A streams a labelled corpus (``benign/`` and ``phishing/`` folders) lazily, alternating classes and holding
only a bounded number of emails in flight, through the same extractors
production uses. Stage 7B cross-fits MemAE so every email's ``memae_loss`` comes
from a model that never saw it, scores the meta-model on out-of-fold
predictions, then fits both on everything and writes them where the runtime
loads them (``FusionMetaModel`` / ``GraphMemAE``), flagged as trained.

Tiers too slow to run per training email are held constant: no screenshot, and
SLM verdict SUSPICIOUS for every email. They must not depend on the label:
mapping ham to BENIGN and spam to CRITICAL would hand the meta-model the answer,
report a perfect AUC, and ship a model that only echoes the SLM.
"""

import argparse
import itertools
import json
import logging
import os
import sys
import warnings
from collections.abc import Generator, Iterable
from concurrent.futures import ALL_COMPLETED, FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

# torch_geometric's import trips this on Python 3.14; it is not actionable here.
warnings.filterwarnings("ignore", message="`torch.jit.script` is not supported", category=FutureWarning)

import numpy as np
import numpy.typing as npt
import torch
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import StratifiedKFold
from torch_geometric.data import Data
from tqdm import tqdm

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:  # `python scripts/train_orchestrator.py` from anywhere
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.config import get_settings  # noqa: E402
from src.core.logger import configure_logging, get_logger, shutdown_logging  # noqa: E402
from src.extractors.mime_parser import unpack_email  # noqa: E402
from src.extractors.url_extractor import extract_urls  # noqa: E402
from src.forensics.auth_analyzer import analyze_identity  # noqa: E402
from src.forensics.route_analyzer import analyze_routing  # noqa: E402
from src.fusion.meta_scorer import FEATURE_NAMES, FusionMetaModel  # noqa: E402
from src.schemas import VerdictLevel  # noqa: E402
from src.topology.graph_builder import build_email_dag  # noqa: E402
from src.topology.memae_model import GraphMemAE  # noqa: E402

logger = get_logger("training")

# modern_2026 (and synthetic_2026) use benign/phishing; easy_ham/spam reproduce the
# SpamAssassin 2002 baseline.
LABEL_DIRECTORIES: Final = {"benign": 0, "phishing": 1, "easy_ham": 0, "spam": 1}
# SpamAssassin ships a "cmds" file of mv commands in every folder; it is not an email.
SKIPPED_FILE_NAMES: Final = frozenset({"cmds"})
MAX_EMAIL_BYTES: Final = 10 * 1024 * 1024
TRAINING_SLM_VERDICT: Final = VerdictLevel.SUSPICIOUS  # label-independent on purpose, see module doc
MEMAE_LOSS_COLUMN: Final = FEATURE_NAMES.index("memae_loss")
MEMAE_EPOCHS: Final = 5
MEMAE_LEARNING_RATE: Final = 0.01
ZERO_DAY_QUANTILE: Final = 0.99
FOLDS: Final = 5
SEED: Final = 42

Example = tuple[npt.NDArray[np.float64], Data, int]


# --- Stage 7A: ingestion ----------------------------------------------------------


def _labelled_paths(data_dir: Path) -> dict[int, list[Path]]:
    """Corpus files grouped by label (from their nearest labelled folder), sorted for determinism."""
    by_label: dict[int, list[Path]] = {label: [] for label in sorted(set(LABEL_DIRECTORIES.values()))}
    for path in sorted(data_dir.rglob("*")):
        if not path.is_file() or path.name in SKIPPED_FILE_NAMES or path.name.startswith("."):
            continue
        folders = [parent.name for parent in path.relative_to(data_dir).parents] + [data_dir.name]
        label = next((LABEL_DIRECTORIES[name] for name in folders if name in LABEL_DIRECTORIES), None)
        if label is not None:
            by_label[label].append(path)
    return by_label


def corpus_generator(data_dir: Path) -> Generator[tuple[bytes, int], None, None]:
    """Lazily yield ``(raw_bytes, label)``; ``easy_ham`` is 0 and ``spam`` is 1.

    Classes alternate, so any prefix (``--debug-slice``) holds both. Only paths are
    listed up front; each file is read when the consumer asks for it.
    """
    streams = [[(path, label) for path in paths] for label, paths in _labelled_paths(data_dir).items()]
    for path, label in (item for row in itertools.zip_longest(*streams) for item in row if item is not None):
        try:
            if path.stat().st_size > MAX_EMAIL_BYTES:
                logger.warning("Oversized corpus file skipped", extra={"event": "training.skipped", "path": path})
                continue
            raw = path.read_bytes()
        except OSError:
            logger.exception("Corpus file unreadable", extra={"event": "training.skipped", "path": path})
            continue
        yield raw, label


def process_single_email(raw_bytes: bytes, label: int) -> Example | None:
    """(10-feature row, delivery DAG, label) via the production extractors, or None on failure.

    Vision features are zero (nothing is detonated offline), the SLM verdict is the
    constant ``TRAINING_SLM_VERDICT``, and ``memae_loss`` is 0 until the trainer
    fills it with cross-fitted losses.
    """
    try:
        message, text, html, _ = unpack_email(raw_bytes)
        identity = analyze_identity(message, get_settings().HIGH_RISK_BRAND_KEYWORDS)
        routing = analyze_routing(message)
        dag = build_email_dag(routing, extract_urls(html, text))
        row = FusionMetaModel._build_feature_vector(
            {**identity, **routing},
            {},
            {"graph_nodes_count": dag.num_nodes, "memae_reconstruction_loss": 0.0},
            TRAINING_SLM_VERDICT,
        )
        return row[0], dag, label
    except Exception:
        logger.exception("Training email could not be processed", extra={"event": "training.email_failed", "label": label})
        return None


def _collect(
    pending: dict[Future[Example | None], int],
    results: dict[int, Example | None],
    progress: tqdm,
    return_when: str,
) -> None:
    done, _ = wait(pending, return_when=return_when)
    for future in done:
        results[pending.pop(future)] = future.result()
        progress.update(1)


def extract_features_concurrently(
    data_dir: Path, limit: int = 0
) -> tuple[list[npt.NDArray[np.float64]], list[Data], list[int]]:
    """Process the corpus (first ``limit`` emails if > 0) on a thread pool.

    At most two emails per worker are in flight, so memory stays flat however large
    the corpus is. Results keep corpus order, whatever order threads finish in.
    """
    total = sum(len(paths) for paths in _labelled_paths(data_dir).values())
    if limit:
        total = min(total, limit)
    emails: Iterable[tuple[bytes, int]] = corpus_generator(data_dir)
    if limit:
        emails = itertools.islice(emails, limit)

    workers = os.cpu_count() or 1
    results: dict[int, Example | None] = {}
    pending: dict[Future[Example | None], int] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool, tqdm(total=total, unit="email", desc="Extracting") as progress:
        for index, (raw, label) in enumerate(emails):
            pending[pool.submit(process_single_email, raw, label)] = index
            if len(pending) >= 2 * workers:
                _collect(pending, results, progress, FIRST_COMPLETED)
        if pending:
            _collect(pending, results, progress, ALL_COMPLETED)

    examples = [example for _, example in sorted(results.items()) if example is not None]
    failed = len(results) - len(examples)
    if failed:
        logger.warning("Some training emails failed", extra={"event": "training.failures", "failed": failed})
    return [row for row, _, _ in examples], [dag for _, dag, _ in examples], [label for _, _, label in examples]


# --- Stage 7B: training -------------------------------------------------------------


def train_memae(dags: list[Data], *, epochs: int = MEMAE_EPOCHS, seed: int = SEED) -> GraphMemAE:
    """A fresh MemAE fitted to ``dags`` (benign routes) with Adam, one graph per step."""
    if not dags:
        raise ValueError("MemAE needs at least one benign graph to learn normal routing from")
    model = GraphMemAE(load_weights=False)
    model.train()
    optimizer = torch.optim.Adam(model.parameters(), lr=MEMAE_LEARNING_RATE)
    order = torch.Generator().manual_seed(seed)
    for epoch in range(epochs):
        epoch_loss = 0.0
        for index in torch.randperm(len(dags), generator=order).tolist():
            optimizer.zero_grad()
            loss = model.reconstruction_loss(dags[index])
            loss.backward()  # type: ignore[no-untyped-call]  # torch leaves Tensor.backward unannotated
            optimizer.step()
            epoch_loss += loss.item()
        logger.info(
            "MemAE epoch finished",
            extra={"event": "training.memae_epoch", "epoch": epoch + 1, "mean_loss": epoch_loss / len(dags)},
        )
    model.eval()
    return model


def cross_fitted_memae_losses(
    dags: list[Data], labels: npt.NDArray[np.int64], splits: list[tuple[npt.NDArray[np.intp], npt.NDArray[np.intp]]]
) -> npt.NDArray[np.float64]:
    """Each email's anomaly loss from a MemAE trained on the other folds' benign emails.

    Scoring benign emails with a MemAE that trained on them would make them look
    unusually normal: a label leak the meta-model would learn instead of the topology.
    """
    losses = np.zeros(len(dags), dtype=np.float64)
    for fold, (train_index, valid_index) in enumerate(splits):
        model = train_memae([dags[i] for i in train_index if labels[i] == 0], seed=SEED + fold)
        for i in valid_index:
            losses[i] = model.compute_anomaly_loss(dags[i])
    return losses


def _forest() -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=100, max_depth=6, random_state=SEED, n_jobs=-1)


def train_and_export(
    X_meta_arrays: npt.NDArray[np.float64],
    dag_list: list[Data],
    y_labels: npt.NDArray[np.int64],
    models_dir: Path,
) -> dict[str, Any]:
    """Cross-validate, fit on everything, write the runtime artifacts; return the training report."""
    class_counts = np.bincount(y_labels, minlength=2)
    folds = min(FOLDS, int(class_counts.min()))
    if folds < 2:
        raise SystemExit(f"Need at least 2 emails of each class to cross-validate; got benign/phishing = {class_counts.tolist()}")
    splits = list(StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED).split(X_meta_arrays, y_labels))

    features = X_meta_arrays.copy()
    losses = cross_fitted_memae_losses(dag_list, y_labels, splits)
    features[:, MEMAE_LOSS_COLUMN] = losses
    # Out-of-fold, so this is how unseen *benign* routes score: 1% of normal mail exceeds it.
    zero_day_threshold = float(np.quantile(losses[y_labels == 0], ZERO_DAY_QUANTILE))

    oof = np.zeros(len(y_labels), dtype=np.float64)
    for train_index, valid_index in splits:
        forest = _forest().fit(features[train_index], y_labels[train_index])
        oof[valid_index] = forest.predict_proba(features[valid_index])[:, list(forest.classes_).index(1)]
    auc = float(roc_auc_score(y_labels, oof))
    report = classification_report(
        y_labels, (oof >= 0.5).astype(int), target_names=["benign", "phishing"], digits=3, zero_division=0
    )
    print(f"\nOut-of-fold ROC AUC ({folds}-fold stratified): {auc:.4f}\n{report}")

    final_forest = _forest().fit(features, y_labels)
    final_memae = train_memae([dag for dag, label in zip(dag_list, y_labels, strict=True) if label == 0])
    final_memae.zero_day_threshold = zero_day_threshold
    meta_path = models_dir / "fusion_meta.joblib"
    memae_path = models_dir / "topology" / "memae.pt"
    onnx_path: Path | None = models_dir / "topology" / "memae.onnx"
    FusionMetaModel.write_bundle(final_forest, meta_path, dummy=False)
    final_memae.save(memae_path, placeholder=False)
    try:
        assert onnx_path is not None
        final_memae.export_onnx(onnx_path)
    except Exception:
        # The runtime scores with the PyTorch checkpoint; the ONNX copy is optional.
        logger.exception("MemAE ONNX export failed", extra={"event": "training.onnx_failed"})
        onnx_path = None

    constant = [name for name, column in zip(FEATURE_NAMES, features.T, strict=True) if np.ptp(column) == 0]
    training_report: dict[str, Any] = {
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "emails": len(y_labels),
        "class_counts": {"benign": int(class_counts[0]), "phishing": int(class_counts[1])},
        "folds": folds,
        "oof_roc_auc": auc,
        "memae_zero_day_threshold": zero_day_threshold,
        "feature_names": list(FEATURE_NAMES),
        # Features with one value in training: the model cannot have learned to use them.
        "constant_features": constant,
        "artifacts": {
            "fusion_meta": str(meta_path),
            "memae": str(memae_path),
            "memae_onnx": str(onnx_path) if onnx_path else None,
        },
    }
    (models_dir / "training_report.json").write_text(json.dumps(training_report, indent=2), encoding="utf-8")
    return training_report


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Train MemAE and the fusion meta-model on a labelled corpus.")
    parser.add_argument("--debug-slice", type=int, default=0, help="only the first N emails (classes alternate); 0 = all")
    parser.add_argument("--data-dir", type=Path, default=settings.BASE_DIR / "data" / "raw" / "modern_2026")
    parser.add_argument("--models-dir", type=Path, default=settings.MODELS_DIR, help="where the runtime loads models")
    parser.add_argument("--extract-only", action="store_true", help="run Stage 7A and stop")
    args = parser.parse_args(argv)
    if args.debug_slice < 0:
        parser.error("--debug-slice must be >= 0")
    if not args.data_dir.is_dir():
        parser.error(f"corpus not found at {args.data_dir} (expected benign/ and phishing/ folders; see scripts/fetch_modern_corpus.py)")

    configure_logging(level=logging.WARNING)
    try:
        X_meta_arrays, dag_list, y_labels = extract_features_concurrently(args.data_dir, args.debug_slice)
        counts = np.bincount(np.asarray(y_labels, dtype=np.int64), minlength=2)
        print(f"Extracted {len(y_labels)} emails (benign {counts[0]}, phishing {counts[1]})")
        if args.extract_only or not y_labels:
            return 0
        report = train_and_export(
            np.vstack(X_meta_arrays), dag_list, np.asarray(y_labels, dtype=np.int64), args.models_dir
        )
        print(f"Artifacts written to {args.models_dir}: {json.dumps(report['artifacts'])}")
        if report["constant_features"]:
            print(f"Held constant in training (the model ignores them): {', '.join(report['constant_features'])}")
    finally:
        shutdown_logging()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
