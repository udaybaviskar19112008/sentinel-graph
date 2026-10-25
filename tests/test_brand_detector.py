import hashlib
import io
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pytest
import torch
from PIL import Image
from torch import nn

from src.schemas import VisionForensics
from src.vision import brand_detector
from src.vision.brand_detector import EMBEDDING_DIM, VisualSpoofDetector


def _image_bytes(mode: str = "RGB", fmt: str = "PNG", size: tuple[int, int] = (1024, 768)) -> bytes:
    rng = np.random.default_rng(7)
    channels = {"RGB": 3, "RGBA": 4, "L": 1}[mode if mode != "P" else "RGB"]
    noise = rng.integers(0, 256, size=(size[1], size[0], channels), dtype=np.uint8).squeeze()
    image = Image.fromarray(noise, mode="RGB" if mode == "P" else mode)
    if mode == "P":
        image = image.convert("P")
    buffer = io.BytesIO()
    image.save(buffer, format=fmt)
    return buffer.getvalue()


@pytest.fixture(scope="module")
def model_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("models") / "vision" / "mobilenetv3.onnx"


@pytest.fixture(scope="module")
def detector(model_path: Path) -> VisualSpoofDetector:
    return VisualSpoofDetector(model_path=model_path)


def test_missing_model_generates_placeholder_with_mobilenet_io(
    detector: VisualSpoofDetector, model_path: Path
) -> None:
    assert model_path.is_file()
    assert detector.is_placeholder
    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    assert session.get_inputs()[0].shape == [1, 3, 224, 224]
    assert session.get_outputs()[0].shape == [1, EMBEDDING_DIM]
    # Atomic export: no temp files left beside the model.
    assert sorted(p.name for p in model_path.parent.iterdir()) == ["mobilenetv3.onnx"]


def test_noise_screenshot_returns_vision_forensics(detector: VisualSpoofDetector) -> None:
    screenshot = _image_bytes()

    result = detector.analyze_screenshot(screenshot)

    assert isinstance(result, VisionForensics)
    assert result.screenshot_hash == hashlib.sha256(screenshot).hexdigest()
    assert result.visual_spoof_score == 0.0
    assert result.detected_brand is None
    assert result.is_credential_harvester is False


def test_existing_model_is_reused_not_regenerated(detector: VisualSpoofDetector, model_path: Path) -> None:
    before = model_path.stat().st_mtime_ns

    again = VisualSpoofDetector(model_path=model_path)

    assert model_path.stat().st_mtime_ns == before
    assert again.is_placeholder  # still recognised as the stand-in after a restart


def test_embedding_is_unit_length_and_deterministic(detector: VisualSpoofDetector) -> None:
    screenshot = _image_bytes()

    first = detector.embed(screenshot)
    second = detector.embed(screenshot)

    assert first.shape == (EMBEDDING_DIM,)
    assert first.dtype == np.float32
    assert np.isfinite(first).all()
    assert np.linalg.norm(first) == pytest.approx(1.0, rel=1e-5)
    np.testing.assert_array_equal(first, second)


@pytest.mark.parametrize(
    ("mode", "fmt"),
    [("RGBA", "PNG"), ("L", "PNG"), ("P", "GIF"), ("RGB", "JPEG"), ("RGB", "WEBP")],
)
def test_other_modes_and_formats_are_normalised(detector: VisualSpoofDetector, mode: str, fmt: str) -> None:
    result = detector.analyze_screenshot(_image_bytes(mode, fmt, size=(320, 200)))

    assert isinstance(result, VisionForensics)


@pytest.mark.parametrize("payload", [b"", b"not an image", _image_bytes()[:200]], ids=["empty", "text", "truncated"])
def test_undecodable_bytes_raise_value_error(detector: VisualSpoofDetector, payload: bytes) -> None:
    with pytest.raises(ValueError, match="could not be decoded"):
        detector.analyze_screenshot(payload)


def test_oversized_images_are_refused_before_decoding(
    detector: VisualSpoofDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(brand_detector, "MAX_IMAGE_PIXELS", 1024 * 768 - 1)

    with pytest.raises(ValueError, match="refusing to decode"):
        detector.analyze_screenshot(_image_bytes())


def test_real_model_is_not_reported_as_placeholder(tmp_path: Path) -> None:
    path = tmp_path / "real.onnx"
    model = nn.Sequential(nn.Conv2d(3, EMBEDDING_DIM, 32, 32), nn.AdaptiveAvgPool2d(1), nn.Flatten()).eval()
    torch.onnx.export(
        model,
        (torch.zeros(1, 3, 224, 224),),
        str(path),
        input_names=["images"],
        output_names=["logits"],
        dynamo=True,
        external_data=False,
        verbose=False,
    )

    detector = VisualSpoofDetector(model_path=path)

    assert detector.is_placeholder is False
    assert detector.embed(_image_bytes()).shape == (EMBEDDING_DIM,)
