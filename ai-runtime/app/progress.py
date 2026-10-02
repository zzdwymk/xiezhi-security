"""Bounded presentation-only progress, separate from the trusted runtime ledger."""
from __future__ import annotations

import asyncio
from contextlib import suppress
from contextvars import ContextVar
from typing import Any, AsyncIterator, Callable

_STAGES = {"ROUTING", "RETRIEVING", "EVIDENCE_READY", "ASSESSING", "ASSESSED", "GENERATING", "CONTRACT_RETRY", "AUTHORIZING"}
_DECISIONS = {"FINALIZE", "REWRITE_QUERY", "CLARIFY"}
_listener: ContextVar[Callable[[dict[str, Any]], None] | None] = ContextVar("public_progress", default=None)


def emit_progress(stage: str, *, count: int | None = None, decision: str | None = None) -> None:
    listener = _listener.get()
    if listener is None or stage not in _STAGES:
        return
    payload: dict[str, Any] = {"stage": stage}
    if type(count) is int and 0 <= count <= 10:
        payload["count"] = count
    if decision in _DECISIONS:
        payload["decision"] = decision
    listener(payload)


async def with_public_progress(events: AsyncIterator[dict[str, Any]]) -> AsyncIterator[tuple[str, Any]]:
    queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue(maxsize=64)
    progress_count = 0

    def publish(payload: dict[str, Any]) -> None:
        nonlocal progress_count
        if progress_count >= 32 or queue.full():
            return
        progress_count += 1
        queue.put_nowait(("progress", payload))

    async def pump() -> None:
        token = _listener.set(publish)
        try:
            async for event in events:
                await queue.put(("event", event))
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await queue.put(("error", error))
        else:
            await queue.put(("done", None))
        finally:
            _listener.reset(token)

    producer = asyncio.create_task(pump())
    try:
        while True:
            kind, payload = await queue.get()
            if kind == "done":
                break
            if kind == "error":
                raise payload
            yield kind, payload
    finally:
        producer.cancel()
        with suppress(asyncio.CancelledError):
            await producer
