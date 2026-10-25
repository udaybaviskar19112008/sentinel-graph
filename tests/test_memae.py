import math
from pathlib import Path

import pytest
import torch
from torch_geometric.data import Data

from src.topology.memae_model import CHECKPOINT_FORMAT, GraphMemAE, hard_shrink


@pytest.fixture
def weights_path(tmp_path: Path) -> Path:
    return tmp_path / "topology" / "memae.pt"


@pytest.fixture
def model(weights_path: Path) -> GraphMemAE:
    return GraphMemAE(weights_path)


def test_missing_weights_write_placeholder_checkpoint(model: GraphMemAE, weights_path: Path) -> None:
    assert weights_path.is_file()
    assert model.is_placeholder
    assert sorted(p.name for p in weights_path.parent.iterdir()) == ["memae.pt"]
    checkpoint = torch.load(weights_path, weights_only=True)
    assert checkpoint["format"] == CHECKPOINT_FORMAT
    assert checkpoint["state_dict"]["memory"].shape == (50, 16)


def test_forward_pass_returns_positive_float_loss_without_autograd(model: GraphMemAE, sample_dag: Data) -> None:
    loss = model.compute_anomaly_loss(sample_dag)

    assert isinstance(loss, float)
    assert math.isfinite(loss) and loss > 0
    assert torch.is_grad_enabled()  # inference_mode did not leak out
    assert all(parameter.grad is None for parameter in model.parameters())


def test_loss_works_inside_callers_no_grad_and_restores_training_mode(
    model: GraphMemAE, sample_dag: Data
) -> None:
    model.train()

    with torch.no_grad():
        loss = model.compute_anomaly_loss(sample_dag)

    assert loss > 0
    assert model.training


def test_forward_shapes_and_sparse_memory_addressing(model: GraphMemAE, sample_dag: Data) -> None:
    probabilities, weights = model(sample_dag.x, sample_dag.edge_index)

    assert probabilities.shape == (7, 7)
    assert bool(((probabilities >= 0) & (probabilities <= 1)).all())
    assert torch.allclose(probabilities, probabilities.t())
    assert weights.shape == (7, 50)
    assert torch.allclose(weights.sum(dim=1), torch.ones(7))
    assert bool(((weights == 0) | (weights >= model.shrink_threshold)).all())
    assert int((weights > 0).sum(dim=1).max()) < 50  # sparse: not every slot contributes


def test_gradients_flow_to_encoder_and_memory_when_training(model: GraphMemAE, sample_dag: Data) -> None:
    model.train()
    probabilities, _ = model(sample_dag.x, sample_dag.edge_index)
    probabilities.sum().backward()

    assert model.memory.grad is not None and bool(model.memory.grad.abs().sum() > 0)
    assert all(p.grad is not None for p in model.encoder_1.parameters())


def test_hard_shrink_falls_back_to_strongest_slot_when_all_weights_are_small() -> None:
    uniform = torch.full((2, 50), 1 / 50)
    uniform[1, 7] += 1e-3

    shrunk = hard_shrink(uniform, 0.05)

    assert not torch.isnan(shrunk).any()
    assert torch.allclose(shrunk.sum(dim=1), torch.ones(2))
    assert int(shrunk[1].argmax()) == 7 and float(shrunk[1, 7]) == pytest.approx(1.0)


def test_saved_weights_are_reloaded_with_identical_scores(model: GraphMemAE, weights_path: Path, sample_dag: Data) -> None:
    before = weights_path.stat().st_mtime_ns

    reloaded = GraphMemAE(weights_path)

    assert weights_path.stat().st_mtime_ns == before
    assert reloaded.is_placeholder
    assert reloaded.compute_anomaly_loss(sample_dag) == model.compute_anomaly_loss(sample_dag)


def test_trained_checkpoint_is_not_reported_as_placeholder(model: GraphMemAE, tmp_path: Path) -> None:
    trained_path = tmp_path / "trained.pt"
    model.save(trained_path, placeholder=False)

    assert GraphMemAE(trained_path).is_placeholder is False


def test_zero_day_threshold_round_trips_and_gates_the_flag(model: GraphMemAE, tmp_path: Path) -> None:
    assert model.zero_day_threshold is None
    assert model.is_zero_day(1e9) is False  # uncalibrated: never claims a zero-day

    model.zero_day_threshold = 0.8
    path = tmp_path / "calibrated.pt"
    model.save(path, placeholder=False)
    reloaded = GraphMemAE(path)

    assert reloaded.zero_day_threshold == pytest.approx(0.8)
    assert reloaded.is_zero_day(0.81) and not reloaded.is_zero_day(0.8)


def test_checkpoint_with_other_architecture_is_rejected(weights_path: Path, model: GraphMemAE) -> None:
    with pytest.raises(ValueError, match="was saved with"):
        GraphMemAE(weights_path, memory_slots=64)


def test_foreign_checkpoint_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "foreign.pt"
    torch.save({"state_dict": {}}, path)

    with pytest.raises(ValueError, match="not a soc-graph-memae"):
        GraphMemAE(path)
