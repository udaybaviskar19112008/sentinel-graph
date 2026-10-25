"""Edge visual brand detection over sandbox screenshots (ONNX Runtime, CPU).

Production loads a quantised MobileNetV3 from ``MODELS_DIR/vision/mobilenetv3.onnx``.
When that file is missing, an untrained stand-in with the same I/O contract is
generated so the pipeline runs end to end. Its embeddings carry no brand meaning,
and the detector says so loudly (``is_placeholder``) for as long as it is in use.
"""

import hashlib
import io
import os
import tempfile
from pathlib import Path
from typing import Final

import numpy as np
import numpy.typing as npt
import onnxruntime as ort
from PIL import Image, UnidentifiedImageError

from src.core.config import get_settings
from src.core.logger import get_logger
from src.schemas import VisionForensics

logger = get_logger(__name__)

INPUT_SIZE: Final = 224
EMBEDDING_DIM: Final = 1000
# Checked against the image header before any pixel is decompressed (decompression bombs).
MAX_IMAGE_PIXELS = 40_000_000
# Output name that marks the generated stand-in, so a restart still knows it is not a real model.
PLACEHOLDER_OUTPUT_NAME: Final = "soc_placeholder_embedding"
_IMAGENET_MEAN: Final = np.array([0.485, 0.456, 0.406], dtype=np.float32)
_IMAGENET_STD: Final = np.array([0.229, 0.224, 0.225], dtype=np.float32)


def _export_placeholder_model(path: Path) -> None:
    # torch is only needed here; a deployment with a real model never imports it.
    import torch
    from torch import nn

    torch.manual_seed(0)
    model = nn.Sequential(
        nn.Conv2d(3, EMBEDDING_DIM, kernel_size=16, stride=16),
        nn.AdaptiveAvgPool2d(1),
        nn.Flatten(),
    ).eval()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Export beside the target and rename, so concurrent workers never load a half-written file.
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}-", suffix=".onnx")
    os.close(handle)
    try:
        with torch.no_grad():
            torch.onnx.export(
                model,
                (torch.zeros(1, 3, INPUT_SIZE, INPUT_SIZE),),
                temp_name,
                input_names=["input"],
                output_names=[PLACEHOLDER_OUTPUT_NAME],
                dynamo=True,
                external_data=False,  # one self-contained file, so the rename is atomic
                verbose=False,  # the exporter's progress output crashes on non-UTF-8 consoles
            )
        os.replace(temp_name, path)
    finally:
        Path(temp_name).unlink(missing_ok=True)


def _preprocess(image_bytes: bytes) -> npt.NDArray[np.float32]:
    """Decode, resize to 224x224, ImageNet-normalise, and lay out as [1, 3, 224, 224]."""
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            width, height = image.size
            if width * height > MAX_IMAGE_PIXELS:
                raise ValueError(
                    f"image is {width}x{height}; refusing to decode more than {MAX_IMAGE_PIXELS} pixels"
                )
            rgb = image.convert("RGB").resize((INPUT_SIZE, INPUT_SIZE), Image.Resampling.BILINEAR)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("image bytes could not be decoded") from exc
    pixels = np.asarray(rgb, dtype=np.float32) / 255.0
    normalised = (pixels - _IMAGENET_MEAN) / _IMAGENET_STD
    return np.ascontiguousarray(normalised.transpose(2, 0, 1)[np.newaxis], dtype=np.float32)


class VisualSpoofDetector:
    """Screenshot -> embedding -> ``VisionForensics``.

    Load once and share: ONNX Runtime sessions are safe to ``run`` from many threads.
    """

    def __init__(self, model_path: Path | None = None) -> None:
        self.model_path = model_path or get_settings().MODELS_DIR / "vision" / "mobilenetv3.onnx"
        if not self.model_path.exists():
            logger.warning(
                "Vision model missing; generating an untrained placeholder",
                extra={"event": "vision.placeholder_generated", "model_path": self.model_path},
            )
            _export_placeholder_model(self.model_path)

        options = ort.SessionOptions()
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self._session = ort.InferenceSession(
            str(self.model_path), sess_options=options, providers=["CPUExecutionProvider"]
        )
        model_input = self._session.get_inputs()[0]
        model_output = self._session.get_outputs()[0]
        if len(model_input.shape) != 4 or model_input.shape[1] != 3:
            raise ValueError(f"{self.model_path} expects input {model_input.shape}, not [N, 3, H, W]")
        self._input_name: str = model_input.name
        self._output_name: str = model_output.name
        self.is_placeholder = model_output.name == PLACEHOLDER_OUTPUT_NAME
        if self.is_placeholder:
            logger.warning(
                "Vision model is an untrained placeholder; visual scores carry no meaning",
                extra={"event": "vision.placeholder_model", "model_path": self.model_path},
            )

    def embed(self, image_bytes: bytes) -> npt.NDArray[np.float32]:
        """L2-normalised embedding of shape (EMBEDDING_DIM,), ready for cosine similarity.

        Raises ValueError for undecodable or oversized images.
        """
        (output,) = self._session.run([self._output_name], {self._input_name: _preprocess(image_bytes)})
        vector = np.asarray(output, dtype=np.float32).reshape(-1)
        norm = float(np.linalg.norm(vector))
        return vector / norm if norm > 0 else vector

    def analyze_screenshot(self, image_bytes: bytes) -> VisionForensics:
        """Hash and embed a screenshot. Brand scoring against centroids arrives in a later phase."""
        digest = hashlib.sha256(image_bytes).hexdigest()
        embedding = self.embed(image_bytes)
        logger.info(
            "Screenshot analyzed",
            extra={
                "event": "vision.analyzed",
                "screenshot_hash": digest,
                "embedding_dim": embedding.shape[0],
                "placeholder_model": self.is_placeholder,
            },
        )
        return VisionForensics(
            screenshot_hash=digest,
            visual_spoof_score=0.0,
            detected_brand=None,
            is_credential_harvester=False,
        )
