'use strict'
const assert = require('node:assert/strict')
const {createAiRelay} = require('../electron/ai-relay.cjs')
const provider = (id, extra = {}) => ({id, name: id, baseUrl: `https://${id}.example/v1`, model: id, apiKey: `secret-${id}`, enabled: true, ...extra})
const ok = text => new Response(JSON.stringify({choices: [{message: {content: text}, finish_reason: 'stop'}]}), {headers: {'content-type': 'application/json'}})
const event = data => `data: ${JSON.stringify(data)}\n\n`
let passed = 0
async function test(name, fn) { await fn(); passed++; console.log(`PASS ${name}`) }
async function fixture(options, fn) {
  const relay = createAiRelay(options), connection = await relay.start()
  const request = async (body = {}, key = connection.apiKey, signal) => fetch(`${connection.baseUrl}/chat/completions`, {method: 'POST', signal, headers: {'Content-Type': 'application/json', Authorization: `Bearer ${key}`}, body: JSON.stringify({messages: [{role: 'user', content: 'hello'}], ...body})})
  try { await fn(relay, request) } finally { await relay.close() }
}
async function main() {
  await test('default deadline allows structured answers taking more than ten seconds', () => fixture({providers: [provider('a')], fetchImpl: async () => {
    await new Promise(resolve => setTimeout(resolve, 10500))
    return ok('{"intent":"ANALYZE","summary":"complete"}')
  }}, async (relay, request) => {
    const response = await request()
    assert.equal(response.status, 200)
    assert.equal((await response.json()).choices[0].message.content, '{"intent":"ANALYZE","summary":"complete"}')
    assert.equal(relay.status().providers[0].failures, 0)
  }))
  await test('HTTP failure retains status and exposes only allowlisted reasons', async () => {
    const cases = [
      [400, {error: {code: 'invalid_responses_request', message: 'invalid codex request secret'}}, 'invalid_responses_request'],
      [404, {error: {code: 'model_not_found', message: 'model secret not found'}}, 'model_not_found'],
      [500, {error: {code: 'get_channel_failed', message: '模型负载已经达到上限 secret'}}, 'upstream_overloaded'],
      [500, {error: {code: 'get_channel_failed', message: 'upstream overloaded secret'}}, 'upstream_overloaded'],
      [503, {error: {code: 'get_channel_failed', message: 'no channels secret'}}, 'upstream_unavailable'],
      [400, {error: {code: 'secret', message: 'overloaded secret'}}, null],
      [500, {error: {message: 'secret'}}, null],
    ]
    for (const [status, body, reason] of cases) {
      await fixture({providers: [provider('a')], fetchImpl: async () => new Response(JSON.stringify(body), {status})}, async (relay, request) => {
        const probe = await relay.testProvider(provider('a'))
        assert.equal(probe.message, `http_${status}`)
        assert.equal(probe.reason, reason)
        assert.ok(!JSON.stringify(probe).includes('secret'))
        const response = await request()
        assert.equal(response.status, 503)
        assert.deepEqual(await response.json(), {error: {type: 'relay_error', code: 'all_providers_unavailable', message: 'all_providers_unavailable'}})
        assert.equal(relay.status().providers[0].lastError, `http_${status}`)
        assert.equal(relay.status().providers[0].lastReason, reason)
        assert.ok(!JSON.stringify(relay.status()).includes('secret'))
      })
    }
  })
  await test('malformed and oversized upstream errors preserve HTTP status without payload leaks', async () => {
    for (const raw of ['secret invalid JSON', JSON.stringify({error: {code: 'model_not_found', message: 'secret'.repeat(15000)}})]) {
      let signal
      const relay = createAiRelay({fetchImpl: async (_, init) => { signal = init.signal; return new Response(raw, {status: 400}) }})
      const result = await relay.testProvider(provider('a'))
      assert.equal(result.message, 'http_400')
      assert.equal(result.reason, null)
      assert.ok(!JSON.stringify(result).includes('secret'))
      assert.equal(signal.aborted, true)
      await relay.close()
    }
  })
  await test('successful recovery clears previous safe reason', async () => {
    let calls = 0
    await fixture({providers: [provider('a')], cooldownMs: 0, fetchImpl: async () => ++calls === 1 ? new Response(JSON.stringify({error: {code: 'model_not_found'}}), {status: 404}) : ok('OK')}, async (relay, request) => {
      assert.equal((await request()).status, 503)
      assert.equal(relay.status().providers[0].lastReason, 'model_not_found')
      assert.equal((await request()).status, 200)
      assert.equal(relay.status().providers[0].lastReason, null)
      assert.equal(relay.status().providers[0].lastError, null)
    })
  })
  await test('provider test sends custom text and returns actual model reply', async () => {
    const relay = createAiRelay({fetchImpl: async (_, init) => {
      const body = JSON.parse(init.body)
      assert.deepEqual(body.messages, [{role: 'user', content: '请用一句话解释 TLS。'}])
      assert.equal(body.max_tokens, 512)
      return ok('TLS 用于保护通信的机密性和完整性。')
    }})
    const result = await relay.testProvider(provider('a'), '  请用一句话解释 TLS。  ')
    assert.equal(result.ok, true)
    assert.equal(result.reply, 'TLS 用于保护通信的机密性和完整性。')
    assert.equal(result.message, '连接成功')
    assert.equal(typeof result.latencyMs, 'number')
    await relay.close()
  })
  await test('provider test rejects empty, nonstring and oversized prompts without requests', async () => {
    let requests = 0
    const relay = createAiRelay({fetchImpl: async () => { requests++; return ok('must not be sent') }})
    for (const prompt of ['', '   ', '\n\t', null, 123, {}, 'x'.repeat(4001)]) {
      const result = await relay.testProvider(provider('a'), prompt)
      assert.equal(result.ok, false)
      assert.equal(result.message, 'invalid_test_prompt')
      assert.equal(result.reply, undefined)
    }
    assert.equal(requests, 0)
    await relay.close()
  })
  await test('provider test defaults to greeting and supports 4000-character boundary', async () => {
    const prompts = []
    const relay = createAiRelay({fetchImpl: async (_, init) => {
      prompts.push(JSON.parse(init.body).messages[0].content)
      return ok('你好，我是 AI 助手。')
    }})
    assert.equal((await relay.testProvider(provider('a'))).reply, '你好，我是 AI 助手。')
    assert.equal((await relay.testProvider(provider('a'), 'x'.repeat(4000))).ok, true)
    assert.deepEqual(prompts, ['你好，请简短介绍自己。', 'x'.repeat(4000)])
    await relay.close()
  })
  await test('incomplete chat JSON falls back without leaking partial text', () => fixture({providers: [provider('a'), provider('b')], fetchImpl: async url => url.includes('a.example') ? new Response(JSON.stringify({choices:[{message:{content:'PARTIAL'}}]}), {headers:{'content-type':'application/json'}}) : ok('complete')}, async (_, request) => {
    const result = await (await request()).json()
    assert.equal(result.choices[0].message.content, 'complete')
  }))
  await test('round robin and credential isolation', () => fixture({providers: [provider('a'), provider('b')], fetchImpl: async (url, init) => {
    const id = new URL(url).hostname[0]
    assert.equal(init.headers.Authorization, `Bearer secret-${id}`)
    assert.equal(JSON.parse(init.body).model, id)
    return ok(id)
  }}, async (relay, request) => {
    for (const expected of ['a', 'b', 'a']) assert.equal((await (await request()).json()).choices[0].message.content, expected)
    assert.equal(relay.status().providers[0].successes, 2)
    assert.ok(!JSON.stringify(relay.status()).includes('secret'))
  }))
  for (const status of [500, 401]) await test(`HTTP ${status} fallback and cooldown`, () => {
    let aCalls = 0
    return fixture({providers: [provider('a'), provider('b')], fetchImpl: async url => {
      if (url.includes('a.example')) { aCalls++; return new Response('secret failure details', {status}) }
      return ok('good')
    }}, async (relay, request) => {
      for (let i = 0; i < 3; i++) assert.equal((await request()).status, 200)
      assert.equal(aCalls, 1)
      assert.equal(relay.status().providers[0].lastError, `http_${status}`)
      assert.ok(relay.status().providers[0].cooldownUntil > Date.now())
    })
  })
  await test('timeout falls back, including fetch implementations ignoring abort', () => fixture({providers: [provider('a'), provider('b')], attemptTimeoutMs: 20, totalTimeoutMs: 200, fetchImpl: async url => url.includes('a.example') ? new Promise(() => {}) : ok('fallback')}, async (relay, request) => {
    assert.equal((await request()).status, 200)
    assert.equal(relay.status().providers[0].lastError, 'timeout')
  }))
  await test('global deadline prevents multiplying timeouts', () => fixture({providers: [provider('a'), provider('b'), provider('c')], attemptTimeoutMs: 70, totalTimeoutMs: 90, fetchImpl: async () => new Promise(() => {})}, async (relay, request) => {
    const began = Date.now()
    assert.equal((await request()).status, 503)
    assert.ok(Date.now() - began < 250)
    assert.equal(relay.status().providers[2].requests, 0)
  }))
  await test('all fail gives stable sanitized error', () => fixture({providers: [provider('a')], fetchImpl: async () => { throw new Error('secret url payload') }}, async (relay, request) => {
    const response = await request()
    assert.equal(response.status, 503)
    assert.equal((await response.json()).error.code, 'all_providers_unavailable')
    assert.equal(relay.status().providers[0].lastError, 'connection_failed')
  }))
  await test('failed SSE never leaks partial text before fallback', () => fixture({providers: [provider('a', {apiMode: 'responses'}), provider('b')], fetchImpl: async url => url.includes('a.example') ? new Response(event({type: 'response.output_text.delta', delta: 'BAD_PARTIAL'}) + event({type: 'response.failed'}), {headers: {'content-type': 'text/event-stream'}}) : ok('good')}, async (_, request) => {
    const response = await request({stream: true}), text = await response.text()
    assert.equal(response.status, 200)
    assert.ok(text.includes('good'))
    assert.ok(!text.includes('BAD_PARTIAL'))
    assert.ok(text.endsWith('data: [DONE]\n\n'))
  }))
  await test('Responses SSE completion and wire format', () => fixture({providers: [provider('a', {apiMode: 'responses'})], fetchImpl: async (url, init) => {
    assert.equal(url, 'https://a.example/v1/responses')
    const body = JSON.parse(init.body)
    assert.equal(body.instructions, 'Be concise')
    assert.equal(body.store, false)
    assert.deepEqual(body.input, [{type: 'message', role: 'user', content: [{type: 'input_text', text: 'hello'}]}])
    assert.equal(init.headers.originator, undefined)
    return new Response(event({type: 'response.output_text.delta', delta: 'OK'}) + event({type: 'response.completed', response: {status: 'completed', output: [{type: 'message', content: [{type: 'output_text', text: 'OK'}]}]}}), {headers: {'content-type': 'text/event-stream'}})
  }}, async (_, request) => {
    assert.equal((await (await request({messages: [{role: 'system', content: 'Be concise'}, {role: 'user', content: 'hello'}]})).json()).choices[0].message.content, 'OK')
  }))
  for (const raw of [event({choices: [{delta: {content: 'partial'}}]}) + 'data: [DONE]\n\n', event({choices: [{delta: {content: ''}, finish_reason: 'stop'}]})]) {
    await test('reject truncated or empty SSE', () => fixture({providers: [provider('a')], fetchImpl: async () => new Response(raw, {headers: {'content-type': 'text/event-stream'}})}, async (_, request) => assert.equal((await request()).status, 503)))
  }
  await test('chat SSE success buffers complete answer', () => fixture({providers: [provider('a')], fetchImpl: async () => new Response(event({choices: [{index: 0, delta: {content: 'O'}}]}) + event({choices: [{index: 0, delta: {content: 'K'}, finish_reason: 'stop'}]}) + 'data: [DONE]\n\n', {headers: {'content-type': 'text/event-stream'}})}, async (_, request) => {
    assert.equal((await (await request()).json()).choices[0].message.content, 'OK')
  }))
  await test('Responses JSON and explicit Codex headers', () => fixture({providers: [provider('a', {apiMode: 'responses', codexHeaders: true})], fetchImpl: async (_, init) => {
    assert.equal(init.headers.originator, 'codex_cli_rs')
    assert.equal(init.headers['User-Agent'], 'codex_cli_rs/secbox')
    return new Response(JSON.stringify({status: 'completed', output: [{type: 'message', content: [{type: 'output_text', text: 'OK'}]}]}), {headers: {'content-type': 'application/json'}})
  }}, async (relay, request) => {
    assert.equal((await request()).status, 200)
    assert.equal((await relay.testProvider(provider('a', {apiMode: 'responses', codexHeaders: true}))).ok, true)
  }))
  await test('Codex profile overrides Chat route and supplies complete request contract', async () => {
    const cacheKeys = new Set()
    let requests = 0
    await fixture({providers: [provider('a', {apiMode: 'chat_completions', codexHeaders: true})], fetchImpl: async (url, init) => {
      requests++
      assert.equal(url, 'https://a.example/v1/responses')
      const body = JSON.parse(init.body)
      assert.equal(body.model, 'a')
      assert.equal(body.stream, true)
      assert.equal(body.store, false)
      assert.ok(body.instructions.trim())
      assert.deepEqual(body.tools, [])
      assert.equal(body.tool_choice, 'auto')
      assert.equal(body.parallel_tool_calls, true)
      assert.deepEqual(body.reasoning, {effort: 'medium', summary: 'auto'})
      assert.deepEqual(body.text, {verbosity: 'low'})
      assert.deepEqual(body.include, ['reasoning.encrypted_content'])
      assert.match(body.prompt_cache_key, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)
      assert.ok(!cacheKeys.has(body.prompt_cache_key))
      cacheKeys.add(body.prompt_cache_key)
      assert.equal(body.max_tokens, undefined)
      assert.equal(body.max_output_tokens, undefined)
      assert.equal(body.messages, undefined)
      assert.equal(init.headers.Authorization, 'Bearer secret-a')
      assert.equal(init.headers.originator, 'codex_cli_rs')
      assert.equal(init.headers['User-Agent'], 'codex_cli_rs/secbox')
      assert.equal(init.headers['OpenAI-Beta'], 'responses=experimental')
      if (requests === 1) {
        assert.equal(body.instructions, 'Be concise')
        assert.deepEqual(body.input, [
          {type: 'message', role: 'user', content: [{type: 'input_text', text: 'hello'}]},
          {type: 'message', role: 'assistant', content: [{type: 'output_text', text: 'Hi'}]},
          {type: 'message', role: 'user', content: [{type: 'input_text', text: 'next'}]},
        ])
      }
      return new Response(JSON.stringify({status: 'completed', output: [{type: 'message', content: [{type: 'output_text', text: 'OK'}]}]}), {headers: {'content-type': 'application/json'}})
    }}, async (relay, request) => {
      const result = await request({max_tokens: 512, messages: [{role: 'system', content: 'Be concise'}, {role: 'user', content: 'hello'}, {role: 'assistant', content: 'Hi'}, {role: 'user', content: 'next'}]})
      assert.equal(result.status, 200)
      assert.equal((await result.json()).choices[0].message.content, 'OK')
      const probe = await relay.testProvider(provider('a', {apiMode: 'chat_completions', codexHeaders: true}))
      assert.equal(probe.ok, true)
      assert.equal(probe.reply, 'OK')
      assert.equal(requests, 2)
    })
  })
  await test('auth and tool boundary', () => fixture({providers: [provider('a')], fetchImpl: async () => { throw new Error('should not fetch') }}, async (_, request) => {
    assert.equal((await request({}, 'wrong')).status, 401)
    assert.equal((await request({tools: [{type: 'function'}]})).status, 400)
  }))
  await test('configuration updates isolate active requests and counters', async () => {
    let release, entered
    const ready = new Promise(resolve => { entered = resolve })
    await fixture({providers: [provider('a')], fetchImpl: async url => {
      if (url.includes('a.example')) { entered(); await new Promise(resolve => { release = resolve }) }
      return ok(new URL(url).hostname[0])
    }}, async (relay, request) => {
      const pending = request()
      await ready
      relay.setProviders([provider('b')])
      release()
      assert.equal((await (await pending).json()).model, 'a')
      assert.equal(relay.status().providers[0].requests, 0)
      assert.equal((await (await request()).json()).model, 'b')
    })
  })
  await test('empty configuration and endpoint validation', async () => {
    await fixture({providers: []}, async (_, request) => {
      const response = await request()
      assert.equal(response.status, 503)
      assert.equal((await response.json()).error.code, 'no_enabled_providers')
    })
    for (const baseUrl of ['http://example.com', 'https://key@example.com', 'https://example.com?key=secret', 'file:///tmp']) assert.throws(() => createAiRelay({providers: [provider('a', {baseUrl})]}))
  })
  await test('client cancellation aborts upstream without fallback or provider penalty', async () => {
    let entered, upstreamAborted, calls = 0
    const started = new Promise(resolve => { entered = resolve })
    const aborted = new Promise(resolve => { upstreamAborted = resolve })
    await fixture({providers: [provider('a'), provider('b')], fetchImpl: async (_, init) => {
      calls++; entered()
      init.signal.addEventListener('abort', upstreamAborted, {once: true})
      return new Promise(() => {})
    }}, async (relay, request) => {
      const controller = new AbortController()
      const pending = request({}, undefined, controller.signal).catch(error => error)
      await started
      controller.abort()
      await pending
      await aborted
      await new Promise(resolve => setTimeout(resolve, 25))
      assert.equal(calls, 1)
      assert.equal(relay.status().providers[0].failures, 0)
      assert.equal(relay.status().providers[0].cooldownUntil, 0)
      assert.equal(relay.status().providers[1].requests, 0)
    })
  })
  await test('cooldown has a distinct stable error code', () => fixture({providers: [provider('a')], fetchImpl: async () => new Response('', {status: 500})}, async (_, request) => {
    assert.equal((await request()).status, 503)
    const response = await request()
    assert.equal(response.status, 503)
    assert.equal((await response.json()).error.code, 'all_providers_cooling_down')
  }))
  await test('request body accepts runtime payloads above 1MB', () => fixture({providers: [provider('a')], fetchImpl: async () => ok('OK')}, async (_, request) => {
    assert.equal((await request({messages: [{role: 'user', content: 'x'.repeat(1024 * 1024 + 1024)}]})).status, 200)
  }))
  console.log(`${passed} AI relay tests passed`)
}
main().catch(error => { console.error(error); process.exitCode = 1 })
