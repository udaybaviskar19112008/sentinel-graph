import dataclasses
from collections.abc import Iterator

import pytest
from torch_geometric.data import Data

from src.cognitive.slm_inference import CognitiveSLM
from src.core.config import get_settings
from src.core.orchestrator import AnalysisEngines
from src.forensics.route_analyzer import RoutingFindings
from src.fusion.meta_scorer import FusionMetaModel
from src.topology.graph_builder import build_email_dag
from src.topology.memae_model import GraphMemAE
from src.vision.brand_detector import VisualSpoofDetector
from tests.factories import StubSandbox, noise_png

THREE_HOP_ROUTE = RoutingFindings(
    route_hop_count=3, private_ip_leak=False, timestamp_regression_flag=False, extracted_ips=()
)
TWO_URLS = ["https://login.evil.example/verify", "https://cdn.evil.example/x7Qz9kP2"]


@pytest.fixture(scope="session", autouse=True)
def _isolated_database(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Scan history goes to a throwaway SQLite file, never the project's soc_intel.db."""
    database = tmp_path_factory.mktemp("history") / "soc_test.db"
    with pytest.MonkeyPatch.context() as env:
        env.setenv("SOC_DATABASE_URL", f"sqlite+aiosqlite:///{database.as_posix()}")
        get_settings.cache_clear()
        yield
    get_settings.cache_clear()


@pytest.fixture
def sample_urls() -> list[str]:
    return list(TWO_URLS)


@pytest.fixture
def sample_dag() -> Data:
    """The 3-hop, 2-URL email graph: 1 sender + 3 hops + 1 receiver + 2 URLs = 7 nodes."""
    return build_email_dag(THREE_HOP_ROUTE, TWO_URLS)


@pytest.fixture(scope="session")
def base_engines(tmp_path_factory: pytest.TempPathFactory) -> AnalysisEngines:
    """Real placeholder models in a temp dir (built once), the dummy SLM and no sandbox."""
    models = tmp_path_factory.mktemp("engine-models")
    memae = GraphMemAE(models / "memae.pt", load_weights=False)
    memae.zero_day_threshold = 0.5
    return AnalysisEngines(
        detector=VisualSpoofDetector(models / "vision" / "mobilenetv3.onnx"),
        memae=memae,
        meta=FusionMetaModel(models / "fusion_meta.joblib"),
        slm=CognitiveSLM(models / "phi3", dummy_token_delay_s=0),
        brands=get_settings().HIGH_RISK_BRAND_KEYWORDS,
        detonate=StubSandbox(None),
    )


@pytest.fixture
def sandbox() -> StubSandbox:
    return StubSandbox(noise_png())


@pytest.fixture
def engines(base_engines: AnalysisEngines, sandbox: StubSandbox) -> AnalysisEngines:
    return dataclasses.replace(base_engines, detonate=sandbox)
