from pathlib import Path

import numpy as np
import pytest

from scripts import run_ablation_study as ablation
from scripts import train_orchestrator as orchestrator
from src.fusion.meta_scorer import FEATURE_NAMES, FEATURES, N_FEATURES
from src.topology.memae_model import GraphMemAE
from tests.synthetic_corpus import write_corpus

SUBSYSTEMS = list(dict.fromkeys(owner for _, owner in FEATURES))


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return write_corpus(tmp_path_factory.mktemp("ablation"), ham=10, spam=10)


# --- modality map ------------------------------------------------------------------------


def test_every_feature_belongs_to_exactly_one_subsystem() -> None:
    indices = [index for subsystem in SUBSYSTEMS for index in ablation.MODALITY_MAP[subsystem]]

    assert sorted(indices) == list(range(N_FEATURES))


def test_modality_indices_point_at_the_right_features() -> None:
    def names(modality: str) -> list[str]:
        return [FEATURE_NAMES[index] for index in ablation.MODALITY_MAP[modality]]

    assert names("CONTENT_HEURISTICS") == ["dga_max_entropy", "nlp_urgency_score"]
    assert names("GNN_ROUTING") == ["memae_loss"]  # index 8, not 0 (that is auth_fail_count)
    assert names("TOPOLOGY_GNN") == ["graph_nodes_count", "memae_loss"]
    assert names("PROTOCOL_FORENSICS") == [
        "auth_fail_count",
        "display_name_spoof_risk",
        "private_ip_leak",
        "timestamp_regression",
    ]
    assert set(ablation.MODALITY_MAP) == {*SUBSYSTEMS, "GNN_ROUTING"}


# --- loaders -------------------------------------------------------------------------------


def test_evaluation_subset_matches_the_trainer_including_cross_fitted_memae(corpus: Path) -> None:
    X_base, y_true = ablation.load_evaluation_subset(data_dir=corpus)

    assert X_base.shape == (20, N_FEATURES) and X_base.dtype == np.float64
    assert np.bincount(y_true).tolist() == [10, 10]
    memae = X_base[:, orchestrator.MEMAE_LOSS_COLUMN]
    assert np.all(memae > 0)  # the trainer's cross-fitted losses, not the extractor's zeros
    rows, _, labels = orchestrator.extract_features_concurrently(corpus)
    others = [index for index in range(N_FEATURES) if index != orchestrator.MEMAE_LOSS_COLUMN]
    np.testing.assert_array_equal(X_base[:, others], np.vstack(rows)[:, others])
    assert y_true.tolist() == labels


def test_limit_keeps_the_first_emails_of_both_classes(corpus: Path) -> None:
    X_base, y_true = ablation.load_evaluation_subset(limit=8, data_dir=corpus)

    assert X_base.shape == (8, N_FEATURES) and np.bincount(y_true).tolist() == [4, 4]


@pytest.fixture
def phishing_only(tmp_path: Path) -> Path:
    return write_corpus(tmp_path / "modern", ham=0, spam=4)


def test_out_of_time_rows_are_scored_by_the_given_memae(phishing_only: Path, tmp_path: Path) -> None:
    path = tmp_path / "memae.pt"
    model = GraphMemAE(path, load_weights=False)
    model.save(path, placeholder=False)

    X_modern = ablation.load_out_of_time_phishing(path, phishing_only)

    assert X_modern.shape == (4, N_FEATURES)
    _, dags, _ = orchestrator.extract_features_concurrently(phishing_only)
    expected = [GraphMemAE(path).compute_anomaly_loss(dag) for dag in dags]
    np.testing.assert_allclose(X_modern[:, orchestrator.MEMAE_LOSS_COLUMN], expected)


def test_out_of_time_refuses_a_missing_memae_without_creating_one(phishing_only: Path, tmp_path: Path) -> None:
    missing = tmp_path / "nowhere" / "memae.pt"

    with pytest.raises(FileNotFoundError, match="missing"):
        ablation.load_out_of_time_phishing(missing, phishing_only)
    assert not missing.exists()


def test_out_of_time_refuses_a_placeholder_memae(phishing_only: Path, tmp_path: Path) -> None:
    path = tmp_path / "memae.pt"
    GraphMemAE(path, load_weights=False).save(path, placeholder=True)

    with pytest.raises(ValueError, match="placeholder"):
        ablation.load_out_of_time_phishing(path, phishing_only)


def test_out_of_time_refuses_legitimate_mail(corpus: Path, tmp_path: Path) -> None:
    path = tmp_path / "memae.pt"
    GraphMemAE(path, load_weights=False).save(path, placeholder=False)

    with pytest.raises(ValueError, match="phishing only"):
        ablation.load_out_of_time_phishing(path, corpus)
