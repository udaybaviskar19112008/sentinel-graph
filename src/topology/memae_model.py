"""Memory-augmented graph autoencoder (MemAE) scoring delivery topologies.

The encoder maps nodes into a latent space; each latent vector is then rebuilt
from a sparse mix of a small memory of "normal" routing prototypes before the
adjacency is decoded. Topologies the memory cannot express reconstruct badly,
so the reconstruction loss is the anomaly score.

Weights live at ``MODELS_DIR/topology/memae.pt``. When that file is missing, a
seeded, untrained checkpoint is written so the pipeline runs end to end; its
scores carry no meaning and ``is_placeholder`` stays true until real weights land.
"""

import os
import tempfile
import warnings
from pathlib import Path
from typing import Any, Final

import torch
import torch.nn.functional as F
from torch import Tensor, nn
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
from torch_geometric.utils import to_undirected

from src.core.config import get_settings
from src.core.logger import get_logger
from src.topology.graph_builder import NODE_FEATURES

logger = get_logger(__name__)

CHECKPOINT_FORMAT: Final = "soc-graph-memae/1"
_EPS: Final = 1e-12


def hard_shrink(weights: Tensor, threshold: float) -> Tensor:
    """Zero addressing weights below ``threshold`` and re-normalise each row to sum to 1.

    Uses the MemAE relaxation ``relu(w - t) * w / |w - t|``, which equals ``w`` above the
    threshold and 0 below while keeping a gradient path. A row with nothing above the
    threshold keeps its single strongest slot rather than reconstructing from nothing.
    """
    shrunk = F.relu(weights - threshold) * weights / (torch.abs(weights - threshold) + _EPS)
    empty = shrunk.sum(dim=1, keepdim=True) <= _EPS
    strongest = F.one_hot(weights.argmax(dim=1), weights.shape[1]).to(weights.dtype) * weights
    shrunk = torch.where(empty, strongest, shrunk)
    return shrunk / shrunk.sum(dim=1, keepdim=True).clamp_min(_EPS)


def _dense_undirected_adjacency(edge_index: Tensor, num_nodes: int) -> Tensor:
    adjacency = torch.zeros(num_nodes, num_nodes)
    undirected = to_undirected(edge_index, num_nodes=num_nodes)
    adjacency[undirected[0], undirected[1]] = 1.0
    return adjacency


class GraphMemAE(nn.Module):
    def __init__(
        self,
        weights_path: Path | None = None,
        *,
        in_channels: int = NODE_FEATURES,
        hidden_channels: int = 32,
        latent_dim: int = 16,
        memory_slots: int = 50,
        shrink_threshold: float = 0.05,
        temperature: float = 0.1,
        load_weights: bool = True,
    ) -> None:
        """``load_weights=False`` gives fresh seeded weights and touches no files (for training)."""
        super().__init__()
        self.config: dict[str, int | float] = {
            "in_channels": in_channels,
            "hidden_channels": hidden_channels,
            "latent_dim": latent_dim,
            "memory_slots": memory_slots,
            "shrink_threshold": shrink_threshold,
            # Softmax over 50 cosine similarities in [-1, 1] averages 0.02 per slot, so without
            # sharpening a 0.05 shrink threshold would erase almost every address.
            "temperature": temperature,
        }
        # Seeded so a generated placeholder (and its scores) is reproducible across machines.
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(0)
            self.encoder_1 = GCNConv(in_channels, hidden_channels)
            self.encoder_2 = GCNConv(hidden_channels, latent_dim)
            self.memory = nn.Parameter(torch.empty(memory_slots, latent_dim))
            nn.init.kaiming_uniform_(self.memory)
        self.shrink_threshold = shrink_threshold
        self.temperature = temperature
        # Loss above which a route counts as unseen ("zero-day"); set by the trainer from
        # benign out-of-fold losses. None means no calibrated threshold exists.
        self.zero_day_threshold: float | None = None

        self.weights_path = weights_path or get_settings().MODELS_DIR / "topology" / "memae.pt"
        if not load_weights:
            self.is_placeholder = True  # until a trainer saves it with placeholder=False
            self.eval()
            return
        if self.weights_path.exists():
            self.is_placeholder = self._load(self.weights_path)
        else:
            logger.warning(
                "MemAE weights missing; writing an untrained placeholder checkpoint",
                extra={"event": "topology.placeholder_generated", "weights_path": self.weights_path},
            )
            self.save(self.weights_path, placeholder=True)
            self.is_placeholder = True
        if self.is_placeholder:
            logger.warning(
                "MemAE weights are an untrained placeholder; anomaly losses carry no meaning",
                extra={"event": "topology.placeholder_model", "weights_path": self.weights_path},
            )
        self.eval()

    def save(self, path: Path, *, placeholder: bool = False) -> None:
        """Write a checkpoint atomically (temp file + rename) next to ``path``."""
        checkpoint = {
            "format": CHECKPOINT_FORMAT,
            "placeholder": placeholder,
            "config": self.config,
            "zero_day_threshold": self.zero_day_threshold,
            "state_dict": self.state_dict(),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}-", suffix=".pt")
        os.close(handle)
        try:
            torch.save(checkpoint, temp_name)
            os.replace(temp_name, path)
        finally:
            Path(temp_name).unlink(missing_ok=True)

    def _load(self, path: Path) -> bool:
        # weights_only: a checkpoint is data, never code (full unpickling would execute it).
        checkpoint: dict[str, Any] = torch.load(path, map_location="cpu", weights_only=True)
        if checkpoint.get("format") != CHECKPOINT_FORMAT:
            raise ValueError(f"{path} is not a {CHECKPOINT_FORMAT} checkpoint")
        if checkpoint.get("config") != self.config:
            raise ValueError(f"{path} was saved with {checkpoint.get('config')}, not {self.config}")
        self.load_state_dict(checkpoint["state_dict"])
        threshold = checkpoint.get("zero_day_threshold")
        self.zero_day_threshold = None if threshold is None else float(threshold)
        return bool(checkpoint.get("placeholder", False))

    def is_zero_day(self, loss: float) -> bool:
        """Whether ``loss`` exceeds the calibrated threshold (never true without one)."""
        return self.zero_day_threshold is not None and loss > self.zero_day_threshold

    def encode(self, x: Tensor, edge_index: Tensor) -> Tensor:
        # Message passing runs both ways: on the directed DAG the sender would never hear
        # from anything but itself.
        undirected = to_undirected(edge_index, num_nodes=x.shape[0])
        hidden = F.relu(self.encoder_1(x, undirected))
        latent: Tensor = self.encoder_2(hidden, undirected)
        return latent

    def address(self, latent: Tensor) -> Tensor:
        """Sparse addressing weights over the memory slots, shape [N, memory_slots]."""
        similarity = F.normalize(latent, dim=1) @ F.normalize(self.memory, dim=1).t()
        return hard_shrink(F.softmax(similarity / self.temperature, dim=1), self.shrink_threshold)

    def decode(self, latent: Tensor) -> tuple[Tensor, Tensor]:
        """Rebuild latents from memory, then predict edges: (adjacency probs, addressing)."""
        weights = self.address(latent)
        rebuilt = weights @ self.memory
        return torch.sigmoid(rebuilt @ rebuilt.t()), weights

    def forward(self, x: Tensor, edge_index: Tensor) -> tuple[Tensor, Tensor]:
        """(adjacency probabilities [N, N], addressing weights [N, memory_slots])."""
        return self.decode(self.encode(x, edge_index))

    def reconstruction_loss(self, dag: Data) -> Tensor:
        """Differentiable mean BCE between predicted and actual adjacency, off the diagonal.

        The inner-product decoder is symmetric, so the target is the undirected adjacency:
        edge direction is fixed by construction and carries no signal. Self-pairs are
        excluded because they only measure latent norm. This is the training objective.
        """
        num_nodes = int(dag.num_nodes)
        probabilities, _ = self(dag.x, dag.edge_index)
        target = _dense_undirected_adjacency(dag.edge_index, num_nodes)
        off_diagonal = ~torch.eye(num_nodes, dtype=torch.bool)
        return F.binary_cross_entropy(probabilities[off_diagonal].clamp(_EPS, 1 - _EPS), target[off_diagonal])

    def compute_anomaly_loss(self, dag: Data) -> float:
        """``reconstruction_loss`` as an anomaly score; higher is stranger. Runs without autograd."""
        was_training = self.training
        self.eval()
        try:
            with torch.inference_mode():
                loss = self.reconstruction_loss(dag)
        finally:
            self.train(was_training)
        value = float(loss)
        if not torch.isfinite(loss):
            raise ValueError(f"MemAE produced a non-finite loss ({value}) for a {int(dag.num_nodes)}-node graph")
        return value

    def export_onnx(self, path: Path) -> None:
        """Export for ONNX Runtime with inputs ``x`` [N, 5] and ``normalized_adjacency`` [N, N].

        GCNConv's sparse message passing has data-dependent branches torch.export cannot
        trace, so the exported graph runs the identical propagation as a dense matmul;
        build its second input with ``normalized_adjacency``. The file is checked against
        this model on two graph sizes before it replaces ``path``.
        """
        import onnxruntime as ort  # only needed here

        dense = _DenseGraphMemAE(self).eval()
        probes = [_chain_graph(nodes, int(self.config["in_channels"])) for nodes in (5, 11)]
        nodes = torch.export.Dim("nodes", min=2, max=4096)
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}-", suffix=".onnx")
        os.close(handle)
        try:
            with torch.no_grad(), warnings.catch_warnings():
                # x and the adjacency share the "nodes" dimension on purpose.
                warnings.filterwarnings("ignore", message="# The axis name: nodes will not be used")
                x, edge_index = probes[0]
                torch.onnx.export(
                    dense,
                    (x, normalized_adjacency(edge_index, x.shape[0])),
                    temp_name,
                    input_names=["x", "normalized_adjacency"],
                    output_names=["adjacency", "addressing"],
                    dynamic_shapes={"x": {0: nodes}, "adjacency": {0: nodes, 1: nodes}},
                    dynamo=True,
                    external_data=False,  # one self-contained file, so the rename is atomic
                    verbose=False,  # the exporter's progress output crashes on non-UTF-8 consoles
                )
            session = ort.InferenceSession(temp_name, providers=["CPUExecutionProvider"])
            for x, edge_index in probes:
                feed = {"x": x.numpy(), "normalized_adjacency": normalized_adjacency(edge_index, x.shape[0]).numpy()}
                exported = torch.from_numpy(session.run(["adjacency"], feed)[0])
                with torch.no_grad():
                    expected, _ = self(x, edge_index)
                if not torch.allclose(exported, expected, atol=1e-4):
                    raise RuntimeError(f"ONNX export diverges from the model on a {x.shape[0]}-node graph")
            os.replace(temp_name, path)
        finally:
            Path(temp_name).unlink(missing_ok=True)


def normalized_adjacency(edge_index: Tensor, num_nodes: int) -> Tensor:
    """Dense GCN propagation matrix D^-1/2 (A + I) D^-1/2 over the undirected graph."""
    adjacency = _dense_undirected_adjacency(edge_index, num_nodes)
    adjacency.fill_diagonal_(1.0)
    inverse_sqrt_degree = adjacency.sum(dim=1).pow(-0.5)
    return inverse_sqrt_degree[:, None] * adjacency * inverse_sqrt_degree[None, :]


class _DenseGraphMemAE(nn.Module):
    """Export view of a ``GraphMemAE``: same weights, GCN propagation as dense matmuls."""

    def __init__(self, model: GraphMemAE) -> None:
        super().__init__()
        self.model = model

    def forward(self, x: Tensor, adjacency: Tensor) -> tuple[Tensor, Tensor]:
        encoder_1, encoder_2 = self.model.encoder_1, self.model.encoder_2
        hidden = F.relu(adjacency @ encoder_1.lin(x) + encoder_1.bias)
        latent = adjacency @ encoder_2.lin(hidden) + encoder_2.bias
        return self.model.decode(latent)


def _chain_graph(nodes: int, features: int) -> tuple[Tensor, Tensor]:
    """A seeded path graph used to trace and verify the ONNX export."""
    generator = torch.Generator().manual_seed(nodes)
    x = torch.rand(nodes, features, generator=generator)
    edge_index = torch.stack([torch.arange(nodes - 1), torch.arange(1, nodes)])
    return x, edge_index
