'use strict';
const assert = require('node:assert/strict');
const { createClient } = require('./test-ai-intent-request.cjs');
const payload = { projectId: 7, targetId: 9, turnId: 'same-turn', prompt: '只规划', userPrompt: '只规划', executionIntent: 'AUTO' };
const terminal = { type: 'done', status: 'COMPLETED', data: { response: { targetId: 9, message: '等待确认', taskIds: [], approvalId: 40, approvalStatus: 'REQUIRED' } } };
const line = event => JSON.stringify(event) + '\n';
const encoder = new TextEncoder();
const tick = () => new Promise(resolve => setImmediate(resolve));
let passed = 0;
async function test(name, run) { await run(); passed++; console.log('PASS ' + name); }
function clock() {
  let now = 0, next = 0;
  const pending = new Map();
  return {
    timers: {
      setTimeout(fn, delay) { const id = ++next; pending.set(id, { at: now + delay, fn }); return id; },
      clearTimeout(id) { pending.delete(id); },
    },
    advance(ms) { now += ms; for (const [id, timer] of [...pending]) if (timer.at <= now) { pending.delete(id); timer.fn(); } },
    get count() { return pending.size; },
  };
}
function openStream(timer) {
  let controller, aborted = false, cancelled = false;
  const client = createClient({ timers: timer.timers, fetch: async (_url, request) => {
    const body = new ReadableStream({
      start(value) { controller = value; },
      cancel() { cancelled = true; },
    });
    request.signal.addEventListener('abort', () => {
      aborted = true;
      if (!cancelled) controller.error(new DOMException('Aborted', 'AbortError'));
    }, { once: true });
    return new Response(body, { headers: { 'content-type': 'application/x-ndjson' } });
  }});
  return { client, send(event) { controller.enqueue(encoder.encode(line(event))); }, get aborted() { return aborted; }, get cancelled() { return cancelled; } };
}
(async () => {
  for (const event of [
    { type: 'plan', plan: { summary: '尚未审批', steps: [] } },
    { type: 'review', answer: '尚未取得本轮完成回执' },
    { ...terminal, data: { ...terminal.data, recorded: true, eventTiming: 'VERIFIED_RECORD' } },
  ]) await test('clean EOF rejects provisional or recorded ' + event.type, async () => {
    const client = createClient({ fetch: async () => new Response(line(event), { headers: { 'content-type': 'application/x-ndjson' } }) });
    await assert.rejects(client.dispatchAiStreaming(payload, () => {}), /没有返回.*结果/);
  });
  await test('live done settles without waiting for socket EOF and closes the reader', async () => {
    const timer = clock(), stream = openStream(timer);
    let settled = false;
    const promise = stream.client.dispatchAiStreaming(payload, () => {}).then(value => { settled = true; return value; });
    await tick(); stream.send(terminal); await tick();
    assert.equal(settled, true);
    assert.equal((await promise).approvalId, 40);
    assert.equal(stream.cancelled, true);
    assert.equal(timer.count, 0);
  });
  await test('silence after the first progress still times out', async () => {
    const timer = clock(), stream = openStream(timer);
    const promise = stream.client.dispatchAiStreaming(payload, () => {});
    const rejected = assert.rejects(promise, error => error.code === 'ECONNABORTED');
    await tick(); stream.send({ type: 'planner_progress', message: '已开始' }); await tick();
    timer.advance(90_001); await tick();
    assert.equal(stream.aborted, true); await rejected; assert.equal(timer.count, 0);
  });
  await test('activity refreshes the deadline instead of imposing a total runtime cutoff', async () => {
    const timer = clock(), stream = openStream(timer);
    const promise = stream.client.dispatchAiStreaming(payload, () => {});
    await tick();
    for (let i = 0; i < 4; i++) {
      timer.advance(60_000); assert.equal(stream.aborted, false);
      stream.send({ type: 'planner_progress', message: '真实进度 ' + i }); await tick();
    }
    stream.send(terminal);
    assert.equal((await promise).approvalId, 40); assert.equal(timer.count, 0);
  });
  await test('terminal error releases the response reader', async () => {
    const timer = clock(), stream = openStream(timer);
    const promise = stream.client.dispatchAiStreaming(payload, () => {});
    const rejected = assert.rejects(promise, /上游失败/);
    await tick(); stream.send({ type: 'error', message: '上游失败' }); await rejected;
    assert.equal(stream.cancelled, true); assert.equal(timer.count, 0);
  });
  console.log(`${passed} AI stream completion checks passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
