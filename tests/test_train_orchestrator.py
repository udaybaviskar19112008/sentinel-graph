import itertools
import json
import types
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pytest
import torch
from sklearn.model_selection import StratifiedKFold
from torch_geometric.data import Data

from scripts import train_orchestrator as orchestrator
from src.core.config import get_settings
from src.fusion.meta_scorer import FEATURE_NAMES, N_FEATURES, FusionMetaModel
from src.topology.memae_model import GraphMemAE, normalized_adjacency
from tests.synthetic_corpus import write_corpus

VISION_AND_SLM = ["screenshot_hash_exists", "visual_spoof_score", "is_cred_harvester", "slm_verdict_severity"]
# The trainer does not compute the content heuristics yet, so they are still constant zero.
NOT_YET_EXTRACTED = ["dga_max_entropy", "nlp_urgency_score"]


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return write_corpus(tmp_path_factory.mktemp("corpus"), ham=12, spam=12)


# --- Stage 7A -----------------------------------------------------------------------


def test_generator_is_lazy_alternates_classes_and_skips_cmds(corpus: Path) -> None:
    emails = orchestrator.corpus_generator(corpus)

    assert isinstance(emails, types.GeneratorType)
    labels = [label for _, label in emails]
    assert labels == [0, 1] * 12  # every prefix holds both classes; no "cmds" files
    first_raw, _ = next(orchestrator.corpus_generator(corpus))
    assert first_raw.startswith(b"Received: ")


def test_labels_come_from_the_nearest_labelled_folder(tmp_path: Path) -> None:
    (tmp_path / "easy_ham" / "nested").mkdir(parents=True)
    (tmp_path / "spam").mkdir()
    (tmp_path / "unlabelled").mkdir()
    (tmp_path / "easy_ham" / "nested" / "a").write_bytes(b"ham")
    (tmp_path / "spam" / "b").write_bytes(b"spam")
    (tmp_path / "spam" / ".hidden").write_bytes(b"skip")
    (tmp_path / "unlabelled" / "c").write_bytes(b"skip")

    assert list(orchestrator.corpus_generator(tmp_path)) == [(b"ham", 0), (b"spam", 1)]


def test_oversized_files_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "spam").mkdir()
    (tmp_path / "spam" / "big").write_bytes(b"x" * 100)
    (tmp_path / "spam" / "small").write_bytes(b"x")
    monkeypatch.setattr(orchestrator, "MAX_EMAIL_BYTES", 10)

    assert list(orchestrator.corpus_generator(tmp_path)) == [(b"x", 1)]


def test_single_email_yields_features_dag_and_label(corpus: Path) -> None:
    raw, label = next(orchestrator.corpus_generator(corpus))

    result = orchestrator.process_single_email(raw, label)

    assert result is not None
    row, dag, returned_label = result
    assert row.shape == (N_FEATURES,) and returned_label == 0
    assert dag.num_nodes == row[FEATURE_NAMES.index("graph_nodes_count")]
    # Offline stand-ins never depend on the label.
    assert row[[FEATURE_NAMES.index(name) for name in VISION_AND_SLM]].tolist() == [0, 0, 0, 1]


def test_failures_are_logged_and_return_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(raw: bytes) -> None:
        raise RuntimeError("parser bug")

    monkeypatch.setattr(orchestrator, "unpack_email", explode)

    assert orchestrator.process_single_email(b"x", 1) is None


def test_concurrent_extraction_matches_sequential_and_honours_limit(corpus: Path) -> None:
    rows, dags, labels = orchestrator.extract_features_concurrently(corpus, limit=10)

    first_ten = itertools.islice(orchestrator.corpus_generator(corpus), 10)
    sequential = [orchestrator.process_single_email(raw, label) for raw, label in first_ten]
    expected = [example for example in sequential if example is not None]
    assert labels == [label for _, _, label in expected]
    np.testing.assert_array_equal(np.vstack(rows), np.vstack([row for row, _, _ in expected]))
    assert [dag.num_nodes for dag in dags] == [dag.num_nodes for _, dag, _ in expected]


# --- Stage 7B -----------------------------------------------------------------------


def test_training_writes_artifacts_the_runtime_loads_as_trained(
    corpus: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    models = tmp_path / "models"

    assert orchestrator.main(["--data-dir", str(corpus), "--models-dir", str(models), "--debug-slice", "20"]) == 0

    output = capsys.readouterr().out
    assert "Out-of-fold ROC AUC" in output and "precision" in output
    report = json.loads((models / "training_report.json").read_text("utf-8"))
    assert report["emails"] == 20 and report["class_counts"] == {"benign": 10, "phishing": 10}
    assert 0.0 <= report["oof_roc_auc"] <= 1.0
    assert report["constant_features"] == VISION_AND_SLM + NOT_YET_EXTRACTED
    phishing = report["oof_phishing_at_0_5"]
    assert set(phishing) == {"precision", "recall", "f1"} and all(0.0 <= v <= 1.0 for v in phishing.values())
    assert "F1" in output
    # One loss curve per fold: an entry per epoch, each [train, held-out benign] and both finite.
    assert len(report["memae_loss_history"]) == report["folds"]
    for history in report["memae_loss_history"]:
        assert len(history) == report["memae_epochs"]
        assert all(len(epoch) == 2 and all(np.isfinite(epoch)) for epoch in history)
    for plot in ("roc_auc_curve.png", "training_loss.png"):
        assert (models / plot).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    meta = FusionMetaModel(models / "fusion_meta.joblib")
    memae = GraphMemAE(models / "topology" / "memae.pt")
    assert meta.is_dummy is False
    assert memae.is_placeholder is False
    assert memae.zero_day_threshold == pytest.approx(report["memae_zero_day_threshold"])
    assert memae.zero_day_threshold is not None and memae.zero_day_threshold > 0
    rows, dags, _ = orchestrator.extract_features_concurrently(corpus, limit=2)
    assert 0.0 <= meta.predict_risk(rows[0]) <= 1.0
    assert memae.compute_anomaly_loss(dags[0]) > 0

    session = ort.InferenceSession(str(models / "topology" / "memae.onnx"), providers=["CPUExecutionProvider"])
    feed = {"x": dags[1].x.numpy(), "normalized_adjacency": normalized_adjacency(dags[1].edge_index, dags[1].num_nodes).numpy()}
    with torch.no_grad():
        expected, _ = memae(dags[1].x, dags[1].edge_index)
    np.testing.assert_allclose(session.run(["adjacency"], feed)[0], expected.numpy(), atol=1e-4)


def test_cross_fitted_losses_come_from_models_that_never_saw_the_email(
    corpus: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, dags, labels = orchestrator.extract_features_concurrently(corpus, limit=12)
    seen_by_fold: list[set[int]] = []
    real_train = orchestrator.train_memae

    def recording_train(fold_dags: list[Data], **kwargs: object) -> GraphMemAE:
        seen_by_fold.append({id(dag) for dag in fold_dags})
        return real_train(fold_dags, epochs=1)

    monkeypatch.setattr(orchestrator, "train_memae", recording_train)
    y = np.asarray(labels)
    splits = list(StratifiedKFold(n_splits=3, shuffle=True, random_state=0).split(np.zeros(len(y)), y))

    losses = orchestrator.cross_fitted_memae_losses(dags, y, splits)

    assert np.all(losses > 0)
    for (_, valid_index), seen in zip(splits, seen_by_fold, strict=True):
        assert not seen & {id(dags[i]) for i in valid_index}  # scored emails were never trained on
        assert all(y[i] == 0 for i, dag in enumerate(dags) if id(dag) in seen)  # benign only


def test_candidates_never_default_to_the_deployed_models_dir() -> None:
    defaults = orchestrator.build_parser().parse_args([])

    assert defaults.models_dir.name == "models_research"
    assert defaults.models_dir != get_settings().MODELS_DIR
    assert defaults.data_dir.name == "research"


def test_single_class_corpus_is_rejected(tmp_path: Path) -> None:
    corpus = write_corpus(tmp_path, ham=4, spam=0)

    with pytest.raises(SystemExit, match="at least 2 emails of each class"):
        orchestrator.main(["--data-dir", str(corpus), "--models-dir", str(tmp_path / "models")])


def test_missing_corpus_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exit_info:
        orchestrator.main(["--data-dir", str(tmp_path / "nope")])

    assert exit_info.value.code == 2
