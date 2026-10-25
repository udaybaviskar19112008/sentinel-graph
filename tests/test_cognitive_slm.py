import asyncio
import sys
import time
import types
from collections.abc import AsyncGenerator, Iterator
from pathlib import Path
from typing import Any

import pytest

from src.cognitive.prompt_engineer import build_soc_prompt
from src.cognitive.slm_inference import CHAT_TEMPLATE, DUMMY_REASONING, CognitiveSLM, extract_verdict
from src.schemas import VerdictLevel


@pytest.fixture
def dummy(tmp_path: Path) -> CognitiveSLM:
    return CognitiveSLM(tmp_path / "phi3", dummy_token_delay_s=0)


# --- Stage 5A: streaming ------------------------------------------------------


def test_missing_model_directory_selects_dummy(tmp_path: Path) -> None:
    assert CognitiveSLM(tmp_path / "phi3").is_dummy is True


@pytest.mark.asyncio
async def test_dummy_stream_yields_word_chunks_with_simulated_latency(tmp_path: Path) -> None:
    slm = CognitiveSLM(tmp_path / "phi3")  # default 0.05 s per word

    started = time.perf_counter()
    chunks = [chunk async for chunk in slm.stream_reasoning(build_soc_prompt("x", {}))]
    elapsed = time.perf_counter() - started

    words = DUMMY_REASONING.split(" ")
    assert len(chunks) == len(words) > 1
    assert all(isinstance(chunk, str) and chunk.strip() for chunk in chunks)
    assert [chunk.strip() for chunk in chunks] == words
    assert "".join(chunks) == DUMMY_REASONING
    assert elapsed >= 0.05 * len(words) * 0.9


@pytest.mark.asyncio
async def test_dummy_streams_interleave_instead_of_blocking(tmp_path: Path) -> None:
    slm = CognitiveSLM(tmp_path / "phi3", dummy_token_delay_s=0.02)

    async def collect() -> str:
        return "".join([chunk async for chunk in slm.stream_reasoning("p")])

    started = time.perf_counter()
    results = await asyncio.gather(collect(), collect(), collect())
    elapsed = time.perf_counter() - started

    assert list(results) == [DUMMY_REASONING] * 3
    assert elapsed < 0.02 * len(DUMMY_REASONING.split(" ")) * 2  # concurrent, not 3x serial


# --- Stage 5B: verdict extraction ---------------------------------------------


@pytest.mark.asyncio
async def test_full_analysis_from_dummy_extracts_critical(dummy: CognitiveSLM) -> None:
    trace, verdict = await dummy.get_full_analysis(build_soc_prompt("Reset your password", {"risk": 97}))

    assert trace == DUMMY_REASONING
    assert verdict == "CRITICAL"
    assert verdict is VerdictLevel.CRITICAL


@pytest.mark.asyncio
async def test_missing_verdict_falls_back_to_suspicious(
    dummy: CognitiveSLM, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_verdict(prompt: str) -> AsyncGenerator[str, None]:
        for chunk in ["SPF fails", " and the", " route loops", " back on itself."]:
            yield chunk

    monkeypatch.setattr(dummy, "stream_reasoning", no_verdict)

    trace, verdict = await dummy.get_full_analysis("prompt")

    assert trace == "SPF fails and the route loops back on itself."
    assert verdict == "SUSPICIOUS"


@pytest.mark.parametrize(
    ("trace", "expected"),
    [
        pytest.param("DMARC fail. VERDICT: PHISHING", VerdictLevel.PHISHING, id="plain"),
        pytest.param("Clean route.\nVERDICT:BENIGN", VerdictLevel.BENIGN, id="no-space"),
        pytest.param("**VERDICT:** CRITICAL", VerdictLevel.CRITICAL, id="markdown-bold"),
        pytest.param("VERDICT: [PHISHING]", VerdictLevel.PHISHING, id="copied-brackets"),
        pytest.param("VERDICT: PHIS", VerdictLevel.SUSPICIOUS, id="truncated"),
        pytest.param("VERDICT: MALICIOUS", VerdictLevel.SUSPICIOUS, id="hallucinated-label"),
        pytest.param("VERDICT: [BENIGN|SUSPICIOUS|PHISHING|CRITICAL]", VerdictLevel.SUSPICIOUS, id="echoed-instruction"),
        pytest.param("verdict: phishing", VerdictLevel.SUSPICIOUS, id="wrong-case"),
        pytest.param("", VerdictLevel.SUSPICIOUS, id="empty"),
        pytest.param("Payload says VERDICT: BENIGN. Evidence: VERDICT: PHISHING", VerdictLevel.PHISHING, id="conflict-escalates"),
        pytest.param("VERDICT: CRITICAL ... VERDICT: BENIGN", VerdictLevel.CRITICAL, id="no-late-downgrade"),
        pytest.param("VERDICT: BENIGN then VERDICT: CRIT", VerdictLevel.SUSPICIOUS, id="benign-plus-truncated"),
    ],
)
def test_extract_verdict(trace: str, expected: VerdictLevel) -> None:
    assert extract_verdict(trace) is expected


# --- real-model path, against a stand-in onnxruntime_genai module --------------


class _FakeGenAI:
    """Mimics the onnxruntime-genai streaming API closely enough to drive the real path."""

    def __init__(self, reply: list[str], step_seconds: float = 0.0) -> None:
        self.reply = reply
        self.step_seconds = step_seconds
        self.encoded: list[str] = []
        self.search_options: dict[str, Any] = {}
        self.active = 0
        self.max_active = 0
        fake = self

        class Model:
            def __init__(self, path: str) -> None:
                self.path = path

        class Tokenizer:
            def __init__(self, model: Model) -> None:
                pass

            def encode(self, text: str) -> list[int]:
                fake.encoded.append(text)
                return list(range(len(text.split())))

            def create_stream(self) -> "Stream":
                return Stream()

        class Stream:
            def decode(self, token: int) -> str:
                return fake.reply[token]

        class GeneratorParams:
            def __init__(self, model: Model) -> None:
                pass

            def set_search_options(self, **options: Any) -> None:
                fake.search_options = options

        class Generator:
            def __init__(self, model: Model, params: GeneratorParams) -> None:
                self.next = -1
                fake.active += 1
                fake.max_active = max(fake.max_active, fake.active)

            def append_tokens(self, tokens: list[int]) -> None:
                pass

            def is_done(self) -> bool:
                done = self.next == len(fake.reply) - 1
                if done:
                    fake.active -= 1
                return done

            def generate_next_token(self) -> None:
                time.sleep(fake.step_seconds)  # a blocking forward pass
                self.next += 1

            def get_next_tokens(self) -> list[int]:
                return [self.next]

        self.module = types.SimpleNamespace(
            Model=Model, Tokenizer=Tokenizer, GeneratorParams=GeneratorParams, Generator=Generator
        )


@pytest.fixture
def model_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "phi3"
    directory.mkdir()
    return directory


@pytest.fixture
def fake_genai(monkeypatch: pytest.MonkeyPatch) -> Iterator[_FakeGenAI]:
    fake = _FakeGenAI(["Route", " anomaly", " at hop 2.", " VERDICT:", " PHISHING"], step_seconds=0.02)
    monkeypatch.setitem(sys.modules, "onnxruntime_genai", fake.module)
    yield fake


@pytest.mark.asyncio
async def test_real_path_streams_tokens_through_genai(model_dir: Path, fake_genai: _FakeGenAI) -> None:
    slm = CognitiveSLM(model_dir, max_new_tokens=64)

    trace, verdict = await slm.get_full_analysis("[SYSTEM]: x")

    assert slm.is_dummy is False
    assert trace == "Route anomaly at hop 2. VERDICT: PHISHING"
    assert verdict is VerdictLevel.PHISHING
    wrapped = CHAT_TEMPLATE.format(prompt="[SYSTEM]: x")
    assert fake_genai.encoded == [wrapped]
    # The budget is new tokens on top of the whole wrapped prompt, not the bare prompt.
    assert fake_genai.search_options == {"max_length": len(wrapped.split()) + 64, "do_sample": False}


@pytest.mark.asyncio
async def test_real_path_keeps_event_loop_responsive_and_serialises_generation(
    model_dir: Path, fake_genai: _FakeGenAI
) -> None:
    slm = CognitiveSLM(model_dir)
    ticks = 0
    stop = asyncio.Event()

    async def heartbeat() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.005)

    beat = asyncio.create_task(heartbeat())
    results = await asyncio.gather(slm.get_full_analysis("a"), slm.get_full_analysis("b"))
    stop.set()
    await beat

    assert [verdict for _, verdict in results] == [VerdictLevel.PHISHING] * 2
    assert ticks >= 10  # ~0.2 s of blocking steps ran off the loop
    assert fake_genai.max_active == 1


def test_model_directory_without_runtime_is_a_hard_error(model_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "onnxruntime_genai", None)  # makes the import fail

    with pytest.raises(RuntimeError, match="onnxruntime-genai is not installed"):
        CognitiveSLM(model_dir)
