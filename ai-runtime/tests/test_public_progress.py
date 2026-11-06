import asyncio
from contextlib import aclosing

from app.progress import emit_model_call, emit_progress, with_public_progress


def test_progress_arrives_while_model_is_still_waiting_and_leaves_result_untouched():
    async def run():
        release = asyncio.Event()
        terminal = {"type": "finish", "ledgerSequence": 1, "answer": "validated result"}

        async def model():
            emit_progress("GENERATING")
            await release.wait()
            yield terminal

        async with aclosing(with_public_progress(model())) as stream:
            assert await asyncio.wait_for(anext(stream), 1) == ("progress", {"stage": "GENERATING"})
            assert not release.is_set()
            release.set()
            kind, result = await anext(stream)
            assert kind == "event" and result is terminal
    asyncio.run(run())


def test_progress_is_request_local_and_contains_only_bounded_public_fields():
    async def run():
        async def collect(count):
            async def events():
                emit_progress("EVIDENCE_READY", count=count)
                await asyncio.sleep(0)
                yield {"request": count}
            return [item async for item in with_public_progress(events())]
        first, second = await asyncio.gather(collect(1), collect(2))
        assert first == [("progress", {"stage": "EVIDENCE_READY", "count": 1}), ("event", {"request": 1})]
        assert second == [("progress", {"stage": "EVIDENCE_READY", "count": 2}), ("event", {"request": 2})]
    asyncio.run(run())


def test_closing_progress_stream_cancels_pending_model_work():
    async def run():
        cancelled = asyncio.Event()
        async def model():
            try:
                emit_progress("ASSESSING")
                await asyncio.Event().wait()
                yield {}
            finally:
                cancelled.set()
        stream = with_public_progress(model())
        await anext(stream)
        await stream.aclose()
        assert cancelled.is_set()
    asyncio.run(run())


def test_progress_volume_and_values_are_bounded_without_dropping_result():
    async def run():
        async def events():
            emit_progress("private-model-content")
            emit_progress("EVIDENCE_READY", count=True, decision="secret")
            for _ in range(100):
                emit_progress("GENERATING")
            yield {"type": "finish"}
        result = [item async for item in with_public_progress(events())]
        assert len([item for item in result if item[0] == "progress"]) == 32
        assert result[0] == ("progress", {"stage": "EVIDENCE_READY"})
        assert result[-1] == ("event", {"type": "finish"})
    asyncio.run(run())


def test_model_call_telemetry_reports_stage_attempt_and_duration_only():
    """The chat connection indicator needs what the model is doing, not what it was told."""

    async def run():
        async def events():
            emit_model_call("ROUTE", "STARTED", attempt=1, timeout_ms=60_000)
            emit_model_call("ROUTE", "SUCCEEDED", attempt=1, elapsed_ms=18_250)
            emit_model_call("GROUNDED", "TIMEOUT", attempt=2, elapsed_ms=60_000)
            yield {"type": "finish"}

        result = [item async for item in with_public_progress(events())]
        assert result == [
            ("progress", {"stage": "MODEL_CALL", "modelStage": "ROUTE", "outcome": "STARTED",
                          "attempt": 1, "timeoutMs": 60000}),
            ("progress", {"stage": "MODEL_CALL", "modelStage": "ROUTE", "outcome": "SUCCEEDED",
                          "attempt": 1, "elapsedMs": 18250}),
            ("progress", {"stage": "MODEL_CALL", "modelStage": "GROUNDED", "outcome": "TIMEOUT",
                          "attempt": 2, "elapsedMs": 60000}),
            ("event", {"type": "finish"}),
        ]
    asyncio.run(run())


def test_model_call_telemetry_drops_unbounded_or_unknown_values():
    async def run():
        async def events():
            emit_model_call("ROUTE", "SUCCEEDED")                       # no duration
            emit_model_call("ROUTE", "STARTED")                         # no ceiling
            emit_model_call("PROMPT", "SUCCEEDED", elapsed_ms=10)       # unknown stage name
            emit_model_call("ROUTE", "PRIVATE_MODEL_OUTPUT", elapsed_ms=10)
            emit_model_call("ROUTE", "SUCCEEDED", attempt=99, elapsed_ms=10)
            emit_model_call("ROUTE", "SUCCEEDED", attempt=1, elapsed_ms=10**9)
            emit_model_call("ROUTE", "STARTED", attempt=1, timeout_ms=10**9)
            emit_model_call("ROUTE", "SUCCEEDED", attempt=1, elapsed_ms=True)
            yield {"type": "finish"}

        result = [item async for item in with_public_progress(events())]
        assert result == [("event", {"type": "finish"})]
    asyncio.run(run())

