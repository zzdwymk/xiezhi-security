import asyncio
from contextlib import aclosing

from app.progress import emit_progress, with_public_progress


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
