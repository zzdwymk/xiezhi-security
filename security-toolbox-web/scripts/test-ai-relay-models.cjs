'use strict'
const assert = require('node:assert/strict')
const {listProviderModels} = require('../electron/ai-relay.cjs')
const json = value => new Response(JSON.stringify(value), {headers: {'content-type': 'application/json'}})
let passed = 0
async function test(name, fn) { await fn(); passed++; console.log(`PASS ${name}`) }
const rejectCode = (promise, code) => assert.rejects(promise, error => error.code === code && error.message === code)

async function main() {
  await test('discovers without configured model, deduplicates and sorts', async () => {
    const result = await listProviderModels({baseUrl: 'https://example.com/v1', apiKey: 'private-key'}, {fetchImpl: async (url, init) => {
      assert.equal(url, 'https://example.com/v1/models')
      assert.equal(init.method, 'GET')
      assert.equal(init.headers.Authorization, 'Bearer private-key')
      assert.equal(init.redirect, 'error')
      assert.equal(init.body, undefined)
      return json({data: [{id: 'model-z'}, {id: 'model-a'}, {id: 'model-z'}, {id: ' model-b '}]})
    }})
    assert.deepEqual(result, {models: ['model-a', 'model-b', 'model-z']})
    assert.ok(!JSON.stringify(result).includes('private-key'))
  })
  await test('correct endpoint roots and completion suffixes', async () => {
    for (const [baseUrl, expected] of [
      ['https://example.com', 'https://example.com/v1/models'],
      ['https://example.com/v1/', 'https://example.com/v1/models'],
      ['https://example.com/custom/root', 'https://example.com/custom/root/models'],
      ['https://example.com/custom/root/chat/completions/', 'https://example.com/custom/root/models'],
      ['https://example.com/custom/root/responses', 'https://example.com/custom/root/models'],
      ['http://localhost:8080/v1', 'http://localhost:8080/v1/models'],
      ['http://127.0.0.1:8080', 'http://127.0.0.1:8080/v1/models'],
      ['http://[::1]:8080', 'http://[::1]:8080/v1/models'],
    ]) await listProviderModels({baseUrl}, {fetchImpl: async url => { assert.equal(url, expected); return json({data: []}) }})
  })
  await test('unsafe endpoints never invoke fetch and never expose supplied secrets', async () => {
    for (const baseUrl of ['http://public.example', 'https://user:secret@example.com', 'https://example.com?key=secret', 'https://example.com#secret', 'file:///secret', 'bad-secret']) {
      await rejectCode(listProviderModels({baseUrl}, {fetchImpl: async () => assert.fail('must not fetch')}), 'invalid_endpoint')
    }
    await rejectCode(listProviderModels({}), 'invalid_endpoint')
  })
  await test('Codex headers are explicit and shared with inference', async () => {
    for (const codexHeaders of [true, false]) await listProviderModels({baseUrl: 'https://example.com', codexHeaders}, {fetchImpl: async (_, init) => {
      assert.equal(init.headers.originator, codexHeaders ? 'codex_cli_rs' : undefined)
      assert.equal(init.headers['User-Agent'], codexHeaders ? 'codex_cli_rs/secbox' : undefined)
      assert.equal(init.headers['OpenAI-Beta'], codexHeaders ? 'responses=experimental' : undefined)
      assert.equal(init.headers.Authorization, undefined)
      return json({data: []})
    }})
  })
  await test('HTTP errors expose only stable code', async () => {
    for (const status of [301, 401, 403, 404, 429, 500]) await rejectCode(listProviderModels({baseUrl: 'https://example.com'}, {fetchImpl: async () => new Response('private-key', {status})}), `http_${status}`)
  })
  await test('malformed upstream responses are rejected', async () => {
    for (const body of [null, {}, {error: {message: 'secret'}}, {data: 'wrong'}, {data: [{}]}, {data: [{id: ''}]}, {data: [{id: 123}]}, {data: [{id: 'x'.repeat(257)}]}, {data: [{id: 'bad\nvalue'}]}]) {
      await rejectCode(listProviderModels({baseUrl: 'https://example.com'}, {fetchImpl: async () => json(body)}), 'invalid_models_response')
    }
    await rejectCode(listProviderModels({baseUrl: 'https://example.com'}, {fetchImpl: async () => new Response('not json secret')}), 'invalid_models_response')
  })
  await test('model count is bounded', async () => {
    await rejectCode(listProviderModels({baseUrl: 'https://example.com'}, {fetchImpl: async () => json({data: Array.from({length: 1001}, (_, i) => ({id: `model-${i}`}))})}), 'too_many_models')
  })
  await test('response size bound aborts upstream', async () => {
    let signal
    await rejectCode(listProviderModels({baseUrl: 'https://example.com'}, {fetchImpl: async (_, init) => { signal = init.signal; return new Response('x'.repeat(4 * 1024 * 1024 + 1)) }}), 'response_too_large')
    assert.equal(signal.aborted, true)
  })
  await test('timeout is bounded even when fetch ignores abort', async () => {
    let signal
    await rejectCode(listProviderModels({baseUrl: 'https://example.com'}, {timeoutMs: 20, fetchImpl: async (_, init) => { signal = init.signal; return new Promise(() => {}) }}), 'timeout')
    assert.equal(signal.aborted, true)
  })
  await test('body reading is included in timeout', async () => {
    let signal
    await rejectCode(listProviderModels({baseUrl: 'https://example.com'}, {timeoutMs: 20, fetchImpl: async (_, init) => {
      signal = init.signal
      return new Response(new ReadableStream({start(controller) { controller.enqueue(new TextEncoder().encode('{"data":')) }}))
    }}), 'timeout')
    assert.equal(signal.aborted, true)
  })
  await test('network exceptions sanitized', async () => {
    await rejectCode(listProviderModels({baseUrl: 'https://example.com'}, {fetchImpl: async () => { throw new Error('url private-key') }}), 'connection_failed')
  })
  console.log(`${passed} model discovery tests passed`)
}
main().catch(error => { console.error(error); process.exitCode = 1 })
