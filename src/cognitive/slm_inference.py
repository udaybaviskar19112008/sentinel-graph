"""Local small-language-model reasoning, streamed token by token.

Inference stays on the box (ONNX Runtime GenAI), so email content and telemetry
never reach an external API. Without model artifacts at ``MODELS_DIR/phi3`` the
engine runs a scripted stand-in (``is_dummy``), and says so loudly, so the
pipeline and its streaming UI work without a multi-gigabyte download.
"""

import asyncio
import re
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any, Final

from src.core.config import get_settings
from src.core.logger import get_logger
from src.schemas import VerdictLevel

logger = get_logger(__name__)

DUMMY_REASONING: Final = (
    "Analyzing Graph MSE... Topological anomaly detected in routing hop 2... "
    "Visual spoofing score 1.0 indicates credential UI redressing... VERDICT: CRITICAL"
)
# Phi-3 instruct chat format; the SOC prompt is the single user turn.
CHAT_TEMPLATE: Final = "<|user|>\n{prompt}<|end|>\n<|assistant|>"

_VERDICT_RE: Final = re.compile(
    r"""
    VERDICT \s* : [\s*\[]*     # tolerate markdown bold and a copied "[" from the instruction
    ([A-Z]+)
    (?! [A-Za-z] | \s* \| )    # a whole word, and not the instruction's "BENIGN|SUSPICIOUS|..." list
    """,
    re.VERBOSE,
)
_VERDICT_WORDS: Final = frozenset(VerdictLevel)
_SEVERITY: Final = list(VerdictLevel)


def extract_verdict(trace: str) -> VerdictLevel:
    """The most severe verdict in ``trace``; missing, hallucinated or truncated -> SUSPICIOUS.

    An unrecognised verdict word counts as SUSPICIOUS and conflicting verdicts resolve
    to the most severe, so payload text echoed by the model can escalate a verdict but
    never downgrade it.
    """
    found = [
        VerdictLevel(word) if word in _VERDICT_WORDS else VerdictLevel.SUSPICIOUS
        for word in _VERDICT_RE.findall(trace)
    ]
    return max(found, key=_SEVERITY.index, default=VerdictLevel.SUSPICIOUS)


class CognitiveSLM:
    """Streams a short forensic deduction from a local SLM (or the scripted dummy)."""

    def __init__(
        self,
        model_dir: Path | None = None,
        *,
        max_new_tokens: int | None = None,
        dummy_token_delay_s: float = 0.05,
    ) -> None:
        settings = get_settings()
        self.model_dir = model_dir or settings.MODELS_DIR / "phi3"
        self.max_new_tokens = max_new_tokens or settings.SLM_MAX_NEW_TOKENS
        self._dummy_token_delay_s = dummy_token_delay_s
        # Generation is CPU-bound: running two at once only makes both slower.
        self._lock = asyncio.Lock()
        self._og: Any = None
        self._model: Any = None
        self._tokenizer: Any = None

        self.is_dummy = not self.model_dir.is_dir()
        if self.is_dummy:
            logger.warning(
                "SLM artifacts missing; using the scripted dummy analyst (its verdicts are fake)",
                extra={"event": "cognitive.dummy_model", "model_dir": self.model_dir},
            )
            return
        try:
            import onnxruntime_genai as og
        except ImportError as exc:  # artifacts deployed without the runtime: a broken install
            raise RuntimeError(f"{self.model_dir} exists but onnxruntime-genai is not installed") from exc
        self._og = og
        self._model = og.Model(str(self.model_dir))
        self._tokenizer = og.Tokenizer(self._model)

    async def stream_reasoning(self, prompt: str) -> AsyncGenerator[str, None]:
        """Yield the deduction as it is generated. Close early with ``contextlib.aclosing``."""
        if self.is_dummy:
            for index, word in enumerate(DUMMY_REASONING.split(" ")):
                await asyncio.sleep(self._dummy_token_delay_s)
                yield word if index == 0 else f" {word}"
            return
        async with self._lock:
            async for chunk in self._stream_tokens(prompt):
                yield chunk

    async def _stream_tokens(self, prompt: str) -> AsyncGenerator[str, None]:
        og = self._og
        tokens = await asyncio.to_thread(self._tokenizer.encode, CHAT_TEMPLATE.format(prompt=prompt))
        params = og.GeneratorParams(self._model)
        # Greedy decoding: the same evidence always produces the same deduction.
        params.set_search_options(max_length=len(tokens) + self.max_new_tokens, do_sample=False)
        generator = og.Generator(self._model, params)
        stream = self._tokenizer.create_stream()
        await asyncio.to_thread(generator.append_tokens, tokens)
        while not generator.is_done():
            # Each step is a full forward pass; keep it off the event loop.
            token = await asyncio.to_thread(self._next_token, generator)
            if text := stream.decode(token):
                yield text

    @staticmethod
    def _next_token(generator: Any) -> int:
        generator.generate_next_token()
        return int(generator.get_next_tokens()[0])

    async def get_full_analysis(self, prompt: str) -> tuple[str, VerdictLevel]:
        """Run the stream to completion; return (analyst trace, extracted verdict)."""
        trace = "".join([chunk async for chunk in self.stream_reasoning(prompt)]).strip()
        verdict = extract_verdict(trace)
        logger.info(
            "SLM analysis complete",
            extra={
                "event": "cognitive.analysis_complete",
                "verdict": verdict,
                "trace_chars": len(trace),
                "dummy_model": self.is_dummy,
            },
        )
        return trace, verdict
