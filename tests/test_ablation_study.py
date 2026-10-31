from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

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


# --- ablation core -------------------------------------------------------------------------


def _informative_matrix(seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """60 rows: column 2 carries the label (plus noise); every other column is noise."""
    rng = np.random.default_rng(seed)
    y = np.repeat([0, 1], 30).astype(np.int64)
    X = rng.random((60, N_FEATURES))
    X[:, 2] = y + rng.normal(0, 0.3, 60)
    return X, y


def test_evaluate_ablation_never_modifies_its_input() -> None:
    X, y = _informative_matrix()
    before = X.copy()

    ablation.evaluate_ablation(X, y, [2, 10, 11])

    np.testing.assert_array_equal(X, before)


def test_removing_the_informative_feature_costs_auc() -> None:
    X, y = _informative_matrix()

    full = ablation.evaluate_ablation(X, y, [])
    without = ablation.evaluate_ablation(X, y, [2])

    assert full["roc_auc"] > 0.9 and without["roc_auc"] < full["roc_auc"] - 0.2
    assert 0.0 <= without["f1_score"] <= 1.0 and full["out_of_time_recall"] is None


def test_dropping_the_content_columns_retrains_the_ten_feature_model() -> None:
    X, y = _informative_matrix(1)
    expected = orchestrator.out_of_fold_probabilities(X[:, :10], y, orchestrator.stratified_splits(y))

    result = ablation.evaluate_ablation(X, y, ablation.MODALITY_MAP["CONTENT_HEURISTICS"])

    assert result["roc_auc"] == roc_auc_score(y, expected)


def test_out_of_time_recall_comes_from_a_forest_fitted_on_every_row() -> None:
    X, y = _informative_matrix()
    unseen_phishing = X[y == 1][:10]

    result = ablation.evaluate_ablation(X, y, [], unseen_phishing)

    forest = orchestrator.make_forest().fit(X, y)
    expected = float(np.mean(forest.predict_proba(unseen_phishing)[:, 1] >= 0.5))
    assert result["out_of_time_recall"] == pytest.approx(expected)


@pytest.mark.parametrize("removed", [[-1], [N_FEATURES], list(range(N_FEATURES))])
def test_invalid_ablations_are_refused(removed: list[int]) -> None:
    X, y = _informative_matrix()

    with pytest.raises(ValueError):
        ablation.evaluate_ablation(X, y, removed)


def test_configurations_are_distinct_experiments_starting_with_the_baseline() -> None:
    removed = [tuple(sorted(columns)) for columns in ablation.ABLATIONS.values()]

    assert removed[0] == ()
    assert len(set(removed)) == len(removed)  # "no content" and "legacy 10D" are one row, not two
    assert all(0 <= index < N_FEATURES for columns in removed for index in columns)


def test_markdown_table_has_one_row_per_configuration() -> None:
    results = {
        label: ablation.AblationResult(
            roc_auc=0.95 - 0.01 * position, f1_score=0.8, precision=0.8, recall=0.8, out_of_time_recall=0.5
        )
        for position, label in enumerate(ablation.ABLATIONS)
    }

    table = ablation.format_markdown(results, np.array([0, 0, 1]), 1000)

    rows = [line for line in table.splitlines() if line.startswith("| ") and not line.startswith("| Configuration")]
    assert len(rows) == len(ablation.ABLATIONS)
    assert "2023–25 phishing caught (n=1000)" in table
    assert rows[0].split("|")[5].strip() == "—"  # the baseline degrades by nothing
    assert rows[1].split("|")[5].strip() == f"{0.01 / 0.95 * 100:.2f}%"
    assert "`dga_max_entropy`, `nlp_urgency_score`" in rows[1]


def test_main_writes_the_table(corpus: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "ablation.md"

    assert ablation.main(["--data-dir", str(corpus), "--out", str(out), "--no-out-of-time"]) == 0

    table = out.read_text("utf-8")
    table_lines = [line for line in table.splitlines() if line.startswith("| ")]
    assert len(table_lines) == len(ablation.ABLATIONS) + 1  # header + one row per configuration
    assert "Written to" in capsys.readouterr().out
