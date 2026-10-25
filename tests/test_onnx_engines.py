"""Stage 2C: both edge engines built from default settings, as a fresh deployment builds them.

Detailed behaviour lives in test_brand_detector.py and test_cognitive_slm.py; this file
checks the out-of-the-box path (an empty MODELS_DIR) and the two engines chained.
"""

import hashlib
from collections.abc import AsyncGenerator, Iterator
from pathlib import Path

import onnxruntime as ort
import pytest

from src.cognitive.prompt_engineer import build_soc_prompt
from src.cognitive.slm_inference import DUMMY_REASONING, CognitiveSLM
from src.core.config import get_settings
from src.schemas import VerdictLevel
from src.vision.brand_detector import VisualSpoofDetector
from tests.factories import noise_png


@pytest.fixture(scope="module")
def models_dir(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Point MODELS_DIR at an empty folder for this module only."""
    root = tmp_path_factory.mktemp("fresh-models")
    with pytest.MonkeyPatch.context() as env:
        env.setenv("SOC_MODELS_DIR", str(root))
        get_settings.cache_clear()
        try:
            yield root
        finally:
            get_settings.cache_clear()


@pytest.fixture(scope="module")
def detector(models_dir: Path) -> VisualSpoofDetector:
    return VisualSpoofDetector()


def test_vision_placeholder_is_generated_under_models_dir(detector: VisualSpoofDetector, models_dir: Path) -> None:
    model_file = models_dir / "vision" / "mobilenetv3.onnx"

    assert detector.model_path == model_file and model_file.is_file()
    assert detector.is_placeholder
    session = ort.InferenceSession(str(model_file), providers=["CPUExecutionProvider"])
    assert session.get_inputs()[0].shape == [1, 3, 224, 224]
    assert session.get_outputs()[0].shape == [1, 1000]


def test_screenshot_analysis_returns_vision_forensics(detector: VisualSpoofDetector) -> None:
    screenshot = noise_png()

    result = detector.analyze_screenshot(screenshot)

    assert result.screenshot_hash == hashlib.sha256(screenshot).hexdigest()
    assert result.visual_spoof_score == 0.0  # placeholder until brand centroids exist


def test_slm_defaults_to_the_dummy_without_phi3_artifacts(models_dir: Path) -> None:
    slm = CognitiveSLM()

    assert slm.model_dir == models_dir / "phi3"
    assert slm.is_dummy


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stream", "expected"),
    [
        pytest.param(["Spoofed sender,", " DMARC fail.", " VERDICT:", " PHISHING"], VerdictLevel.PHISHING, id="clean"),
        pytest.param(["Unclear.", " VERDICT: MAYBE"], VerdictLevel.SUSPICIOUS, id="hallucinated"),
        pytest.param(["Route looks odd but no verdict line."], VerdictLevel.SUSPICIOUS, id="missing"),
    ],
)
async def test_async_stream_verdict_extraction(
    models_dir: Path, monkeypatch: pytest.MonkeyPatch, stream: list[str], expected: VerdictLevel
) -> None:
    slm = CognitiveSLM()

    async def scripted(prompt: str) -> AsyncGenerator[str, None]:
        for chunk in stream:
            yield chunk

    monkeypatch.setattr(slm, "stream_reasoning", scripted)

    trace, verdict = await slm.get_full_analysis("prompt")

    assert trace == "".join(stream).strip()
    assert verdict is expected


@pytest.mark.asyncio
async def test_vision_evidence_flows_into_the_slm_prompt(detector: VisualSpoofDetector, models_dir: Path) -> None:
    vision = detector.analyze_screenshot(noise_png())
    prompt = build_soc_prompt("Your Apple ID is locked.", {"vision": vision})
    slm = CognitiveSLM(dummy_token_delay_s=0)

    trace, verdict = await slm.get_full_analysis(prompt)

    assert f'"screenshot_hash":"{vision.screenshot_hash}"' in prompt
    assert trace == DUMMY_REASONING and verdict is VerdictLevel.CRITICAL
