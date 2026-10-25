"""Email delivery topology as a PyTorch Geometric DAG.

Nodes are laid out sender, relay hops (oldest first), receiver, then URLs, and
every edge points from a lower to a higher index, so the graph is acyclic by
construction.
"""

import math
from collections import Counter
from enum import IntEnum
from typing import Final, TypedDict

import torch
from torch_geometric.data import Data

from src.core.config import get_settings
from src.core.logger import get_logger
from src.forensics.route_analyzer import RoutingFindings

logger = get_logger(__name__)


class NodeType(IntEnum):
    SENDER = 0
    RELAY_HOP = 1
    RECEIVER = 2
    URL = 3


NODE_FEATURES: Final = len(NodeType) + 1  # one-hot node type + one scalar score


def url_entropy(url: str) -> float:
    """Shannon entropy of the URL's characters, normalised to [0, 1] by its maximum, log2(len)."""
    if len(url) < 2:
        return 0.0
    counts = Counter(url)
    entropy = -sum(n / len(url) * math.log2(n / len(url)) for n in counts.values())
    return entropy / math.log2(len(url))


def build_email_dag(route_data: RoutingFindings, urls: list[str]) -> Data:
    """Sender -> hop 1 -> ... -> hop N -> receiver, plus sender -> every URL.

    Node features ``x`` are ``[N, 5]``: the one-hot ``NodeType`` and a score in [0, 1],
    which is the node's position along the delivery path for route nodes and the
    normalised character entropy for URL nodes. Hop and URL counts are capped by
    ``GRAPH_MAX_HOPS`` / ``GRAPH_MAX_URLS``.
    """
    hop_count = route_data["route_hop_count"]
    if isinstance(hop_count, bool) or not isinstance(hop_count, int) or hop_count < 0:
        raise ValueError(f"route_hop_count must be a non-negative int, got {hop_count!r}")

    settings = get_settings()
    unique_urls = list(dict.fromkeys(urls))
    hops = min(hop_count, settings.GRAPH_MAX_HOPS)
    kept_urls = graph_urls(urls)
    if hops < hop_count or len(kept_urls) < len(unique_urls):
        logger.warning(
            "Email graph truncated to size limits",
            extra={
                "event": "topology.graph_truncated",
                "hop_count": hop_count,
                "url_count": len(unique_urls),
                "max_hops": settings.GRAPH_MAX_HOPS,
                "max_urls": settings.GRAPH_MAX_URLS,
            },
        )

    route_length = hops + 2  # sender + hops + receiver
    node_types = [NodeType.SENDER, *[NodeType.RELAY_HOP] * hops, NodeType.RECEIVER]
    node_types += [NodeType.URL] * len(kept_urls)
    scores = [position / (route_length - 1) for position in range(route_length)]
    scores += [url_entropy(url) for url in kept_urls]

    # Consecutive route nodes form the delivery chain; the sender links to every URL.
    edges = [(position, position + 1) for position in range(route_length - 1)]
    edges += [(0, route_length + offset) for offset in range(len(kept_urls))]

    one_hot = torch.nn.functional.one_hot(torch.tensor(node_types), num_classes=len(NodeType))
    x = torch.cat([one_hot.to(torch.float32), torch.tensor(scores, dtype=torch.float32).unsqueeze(1)], dim=1)
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    return Data(x=x, edge_index=edge_index)


def graph_urls(urls: list[str]) -> list[str]:
    """The URLs that become graph nodes, in node order: unique, capped by ``GRAPH_MAX_URLS``."""
    return list(dict.fromkeys(urls))[: get_settings().GRAPH_MAX_URLS]


class GraphNode(TypedDict):
    id: str
    kind: str  # NodeType name
    label: str
    score: float  # the node's feature score: path position, or URL entropy


class GraphEdge(TypedDict):
    id: str
    source: str
    target: str


class GraphLayout(TypedDict):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


def describe_email_dag(dag: Data, urls: list[str]) -> GraphLayout:
    """JSON-ready nodes and edges of a DAG from ``build_email_dag`` (positions are the client's job)."""
    kinds = [NodeType(int(kind)) for kind in dag.x[:, : len(NodeType)].argmax(dim=1).tolist()]
    scores = [float(score) for score in dag.x[:, -1].tolist()]
    labels = iter(graph_urls(urls))
    nodes: list[GraphNode] = []
    hop = 0
    for index, (kind, score) in enumerate(zip(kinds, scores, strict=True)):
        if kind is NodeType.RELAY_HOP:
            hop += 1
            label = f"Relay hop {hop}"
        elif kind is NodeType.URL:
            label = next(labels)
        else:
            label = kind.name.title()
        nodes.append(GraphNode(id=str(index), kind=kind.name, label=label, score=round(score, 4)))
    edges = [
        GraphEdge(id=f"e{source}-{target}", source=str(source), target=str(target))
        for source, target in dag.edge_index.t().tolist()
    ]
    return GraphLayout(nodes=nodes, edges=edges)
