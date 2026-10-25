import json
from pathlib import Path

import networkx as nx
import pytest
import torch
from torch_geometric.data import Data
from torch_geometric.utils import to_networkx

from src.core.config import get_settings
from src.core.logger import LOG_FILE_NAME, configure_logging, shutdown_logging
from src.forensics.route_analyzer import RoutingFindings
from src.topology.graph_builder import NODE_FEATURES, NodeType, build_email_dag, describe_email_dag, url_entropy


def _route(hops: int) -> RoutingFindings:
    return RoutingFindings(route_hop_count=hops, private_ip_leak=False, timestamp_regression_flag=False)


def _edges(data: Data) -> list[tuple[int, int]]:
    return [(int(s), int(d)) for s, d in data.edge_index.t().tolist()]


def _types(data: Data) -> list[int]:
    return [int(t) for t in data.x[:, : len(NodeType)].argmax(dim=1).tolist()]


def test_three_hops_two_urls_gives_seven_nodes_and_directed_chain(sample_dag: Data) -> None:
    sample_dag.validate(raise_on_error=True)

    assert sample_dag.num_nodes == 7
    assert sample_dag.x.shape == (7, NODE_FEATURES)
    assert sample_dag.x.dtype == torch.float32
    assert sample_dag.edge_index.shape == (2, 6)
    assert sample_dag.edge_index.dtype == torch.long
    assert _types(sample_dag) == [0, 1, 1, 1, 2, 3, 3]
    assert _edges(sample_dag) == [
        (0, 1),  # sender -> hop 1
        (1, 2),  # hop 1 -> hop 2
        (2, 3),  # hop 2 -> hop 3
        (3, 4),  # hop 3 -> receiver
        (0, 5),  # sender -> URL 1
        (0, 6),  # sender -> URL 2
    ]


def test_graph_is_a_dag_with_single_source(sample_dag: Data) -> None:
    graph = to_networkx(sample_dag)

    assert nx.is_directed_acyclic_graph(graph)
    assert [node for node, degree in graph.in_degree() if degree == 0] == [0]
    assert all(source < target for source, target in _edges(sample_dag))


def test_feature_rows_are_one_hot_plus_bounded_score(sample_dag: Data, sample_urls: list[str]) -> None:
    one_hot, score = sample_dag.x[:, : len(NodeType)], sample_dag.x[:, -1]

    assert torch.equal(one_hot.sum(dim=1), torch.ones(7))
    assert score[:5].tolist() == pytest.approx([0.0, 0.25, 0.5, 0.75, 1.0])
    assert score[5:].tolist() == pytest.approx([url_entropy(url) for url in sample_urls])
    assert bool(((score >= 0) & (score <= 1)).all())


def test_url_entropy_ranks_random_tokens_above_repetition() -> None:
    assert url_entropy("") == 0.0
    assert url_entropy("https://aaaa.example/aaaaaaaa") < url_entropy("https://x7qz9kp2.example/Zr8Lw3vQ")
    assert 0.0 < url_entropy("https://login.evil.example/verify") <= 1.0


def test_direct_delivery_without_relays() -> None:
    data = build_email_dag(_route(0), [])

    assert _types(data) == [NodeType.SENDER, NodeType.RECEIVER]
    assert _edges(data) == [(0, 1)]


def test_duplicate_urls_become_one_node() -> None:
    data = build_email_dag(_route(1), ["https://a.example/", "https://b.example/", "https://a.example/"])

    assert _types(data) == [0, 1, 2, 3, 3]
    assert _edges(data) == [(0, 1), (1, 2), (0, 3), (0, 4)]


def test_oversized_routes_are_capped_and_logged(tmp_path: Path) -> None:
    settings = get_settings()
    shutdown_logging()
    configure_logging(log_dir=tmp_path, level="DEBUG")
    try:
        urls = [f"https://evil.example/{i}" for i in range(settings.GRAPH_MAX_URLS + 5)]
        data = build_email_dag(_route(10_000), urls)
    finally:
        shutdown_logging()

    assert data.num_nodes == 1 + settings.GRAPH_MAX_HOPS + 1 + settings.GRAPH_MAX_URLS
    events = [json.loads(line) for line in (tmp_path / LOG_FILE_NAME).read_text("utf-8").splitlines()]
    (truncated,) = [e for e in events if e.get("event") == "topology.graph_truncated"]
    assert truncated["hop_count"] == 10_000


@pytest.mark.parametrize("bad", [-1, 2.5, "3", True, None])
def test_invalid_hop_count_is_rejected(bad: object) -> None:
    route = {"route_hop_count": bad, "private_ip_leak": False, "timestamp_regression_flag": False}

    with pytest.raises(ValueError, match="route_hop_count"):
        build_email_dag(route, [])  # type: ignore[arg-type]


def test_describe_email_dag_labels_every_node_in_order(sample_dag: Data, sample_urls: list[str]) -> None:
    layout = describe_email_dag(sample_dag, sample_urls + sample_urls)  # duplicates collapse, as in the DAG

    assert [(n["id"], n["kind"], n["label"]) for n in layout["nodes"]] == [
        ("0", "SENDER", "Sender"),
        ("1", "RELAY_HOP", "Relay hop 1"),
        ("2", "RELAY_HOP", "Relay hop 2"),
        ("3", "RELAY_HOP", "Relay hop 3"),
        ("4", "RECEIVER", "Receiver"),
        ("5", "URL", sample_urls[0]),
        ("6", "URL", sample_urls[1]),
    ]
    assert [(int(e["source"]), int(e["target"])) for e in layout["edges"]] == _edges(sample_dag)
    assert len({e["id"] for e in layout["edges"]}) == len(layout["edges"])
    assert [n["score"] for n in layout["nodes"]][:5] == [0.0, 0.25, 0.5, 0.75, 1.0]
    assert json.loads(json.dumps(layout)) == layout
