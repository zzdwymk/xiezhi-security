'use strict'

const http = require('node:http')
const { randomBytes, randomUUID, timingSafeEqual } = require('node:crypto')

const MAX_BODY = 2 * 1024 * 1024
const MAX_RESPONSE = 4 * 1024 * 1024
class RelayError extends Error {
  constructor(code, reason = null) { super(code); this.code = code; this.reason = reason }
}

async function upstreamHttpError(response) {
  let reason = null
  try {
    const body = JSON.parse(await readLimited(response, 64 * 1024))
    const code = body?.error?.code || body?.error?.type || body?.code
    if (code === 'invalid_responses_request' || code === 'model_not_found') reason = code
    else if (code === 'get_channel_failed') {
      const message = body?.error?.message
      reason = typeof message === 'string' && /overload|负载|上限/i.test(message) ? 'upstream_overloaded' : 'upstream_unavailable'
    }
  } catch { /* Never expose raw upstream payloads, including malformed or oversized errors. */ }
  return new RelayError(`http_${response.status}`, reason)
}

function endpoint(provider, operation) {
  let url
  try { url = new URL(provider.baseUrl) } catch { throw new RelayError('invalid_endpoint') }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  const loopback = hostname === 'localhost' || hostname === '::1' || /^127\.\d+\.\d+\.\d+$/.test(hostname)
  if (url.username || url.password || url.search || url.hash || !['http:', 'https:'].includes(url.protocol)
    || (url.protocol === 'http:' && !loopback)) throw new RelayError('invalid_endpoint')
  const suffix = operation === 'models' ? '/models' : provider.apiMode === 'responses' ? '/responses' : '/chat/completions'
  let path = url.pathname.replace(/\/+$/, '').replace(/\/(?:chat\/completions|responses)$/, '')
  if (!path) path = '/v1'
  url.pathname = path + suffix
  return url.toString()
}

function providerHeaders(provider, accept = 'application/json, text/event-stream') {
  const headers = {'Content-Type': 'application/json', Accept: accept}
  if (provider.apiKey) headers.Authorization = `Bearer ${provider.apiKey}`
  if (provider.codexHeaders === true) {
    headers['OpenAI-Beta'] = 'responses=experimental'
    headers.originator = 'codex_cli_rs'
    headers['User-Agent'] = 'codex_cli_rs/secbox'
  }
  return headers
}

async function listProviderModels(provider, {fetchImpl = globalThis.fetch, timeoutMs = 10000} = {}) {
  if (!provider || typeof provider.baseUrl !== 'string') throw new RelayError('invalid_endpoint')
  const url = endpoint(provider, 'models')
  const controller = new AbortController()
  let timer
  try {
    const operation = async () => {
      const response = await fetchImpl(url, {method: 'GET', headers: providerHeaders(provider, 'application/json'), signal: controller.signal, redirect: 'error'})
      if (!response.ok) throw await upstreamHttpError(response)
      const raw = await readLimited(response)
      let body
      try { body = JSON.parse(raw) } catch { throw new RelayError('invalid_models_response') }
      if (!body || body.error || !Array.isArray(body.data)) throw new RelayError('invalid_models_response')
      const models = new Set()
      for (const item of body.data) {
        // Bound model count and each identifier before it enters renderer options.
        if (!item || typeof item.id !== 'string' || !item.id.trim() || item.id.length > 256 || /[\u0000-\u001f\u007f]/.test(item.id)) throw new RelayError('invalid_models_response')
        models.add(item.id.trim())
        if (models.size > 1000) throw new RelayError('too_many_models')
      }
      return {models: [...models].sort()}
    }
    return await Promise.race([operation(), new Promise((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new RelayError('timeout')) }, Math.max(1, timeoutMs))
    })])
  } catch (error) {
    if (error instanceof RelayError) throw error
    throw new RelayError(controller.signal.aborted ? 'timeout' : 'connection_failed')
  } finally { clearTimeout(timer); controller.abort() }
}

function normalize(providers) {
  if (!Array.isArray(providers) || providers.length > 32) throw new RelayError('invalid_providers')
  const ids = new Set()
  return providers.map(p => {
    if (!p || typeof p.id !== 'string' || !p.id || ids.has(p.id) || typeof p.model !== 'string'
      || !p.model.trim() || typeof p.baseUrl !== 'string') throw new RelayError('invalid_provider')
    ids.add(p.id)
    const provider = { id: p.id, name: String(p.name || p.id), baseUrl: p.baseUrl, model: p.model.trim(),
      apiKey: String(p.apiKey || ''), enabled: p.enabled !== false, apiMode: p.apiMode === 'responses' || p.codexHeaders === true ? 'responses' : 'chat_completions', codexHeaders: p.codexHeaders === true }
    endpoint(provider)
    return { provider, requests: 0, successes: 0, failures: 0, lastError: null, lastReason: null, cooldownUntil: 0, lastLatencyMs: null }
  })
}

function textContent(content) {
  if (typeof content === 'string') return content
  if (Array.isArray(content) && content.every(x => x && ['text', 'input_text', 'output_text'].includes(x.type) && typeof x.text === 'string')) return content.map(x => x.text).join('\n')
  throw new RelayError('text_messages_required')
}

function validateRequest(body) {
  if (!body || !Array.isArray(body.messages) || !body.messages.length || body.messages.length > 256
    || (body.tools && body.tools.length) || (body.functions && body.functions.length)) throw new RelayError('text_messages_required')
  return body.messages.map(m => {
    if (!m || !['system', 'developer', 'user', 'assistant'].includes(m.role)) throw new RelayError('text_messages_required')
    return { role: m.role, content: textContent(m.content) }
  })
}

function upstreamBody(provider, body, messages) {
  if (provider.apiMode === 'responses') {
    const instructions = messages.filter(m => ['system', 'developer'].includes(m.role)).map(m => m.content).join('\n\n')
    const input = messages.filter(m => !['system', 'developer'].includes(m.role)).map(m => ({type: 'message', role: m.role,
      content: [{type: m.role === 'assistant' ? 'output_text' : 'input_text', text: m.content}]}))
    const result = { model: provider.model, instructions, input, store: false, stream: true }
    if (provider.codexHeaders) {
      Object.assign(result, {instructions: instructions || 'You are a concise assistant.', tools: [], tool_choice: 'auto',
        parallel_tool_calls: true, reasoning: {effort: 'medium', summary: 'auto'}, text: {verbosity: 'low'},
        include: ['reasoning.encrypted_content'], prompt_cache_key: randomUUID()})
    }
    if (Number.isInteger(body.max_tokens) && !provider.codexHeaders) result.max_output_tokens = body.max_tokens
    return result
  }
  const result = {model: provider.model, messages, stream: false}
  for (const key of ['temperature', 'top_p', 'max_tokens', 'max_completion_tokens', 'response_format', 'stop', 'seed']) {
    if (body[key] !== undefined) result[key] = body[key]
  }
  return result
}

async function readLimited(response, limit = MAX_RESPONSE) {
  if (!response.body) return ''
  const chunks = []
  let size = 0
  for await (const chunk of response.body) {
    const buffer = Buffer.from(chunk)
    size += buffer.length
    if (size > limit) throw new RelayError('response_too_large')
    chunks.push(buffer)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function responseText(data) {
  if (data.error || (data.status && data.status !== 'completed')) throw new RelayError('upstream_incomplete')
  const output = (data.output || []).filter(o => o.type === 'message').flatMap(o => o.content || [])
    .filter(c => c.type === 'output_text').map(c => c.text || '').join('')
  return output || data.output_text || ''
}

function decodeResponse(raw, contentType, mode) {
  let answer = '', completion = null
  if (/text\/event-stream/i.test(contentType) || /^\s*(?:event:|data:)/.test(raw)) {
    let completed = false
    for (const block of raw.replace(/\r\n/g, '\n').split(/\n\n/)) {
      const event = block.split('\n').find(line => line.startsWith('event:'))?.slice(6).trim()
      const data = block.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n')
      if (event && /(?:error|failed|incomplete)$/.test(event)) throw new RelayError('upstream_incomplete')
      if (!data) continue
      if (data === '[DONE]') continue
      let value
      try { value = JSON.parse(data) } catch { throw new RelayError('invalid_upstream_response') }
      if (value.error || /(?:error|failed|incomplete)$/.test(value.type || '')) throw new RelayError('upstream_incomplete')
      if (mode === 'responses') {
        if (value.type === 'response.output_text.delta') answer += value.delta || ''
        if (value.type === 'response.completed') { answer = responseText(value.response); completed = true }
      } else {
        const choice = value.choices?.find(c => c.index === 0) || value.choices?.[0]
        if (typeof choice?.delta?.content === 'string') answer += choice.delta.content
        if (choice?.finish_reason === 'stop') completed = true
        else if (choice?.finish_reason) throw new RelayError('upstream_incomplete')
      }
    }
    // A terminal marker alone does not establish a successful model completion.
    if (!completed) throw new RelayError('upstream_incomplete')
  } else {
    let value
    try { value = JSON.parse(raw) } catch { throw new RelayError('invalid_upstream_response') }
    if (value.error) throw new RelayError('upstream_error')
    if (mode === 'responses') answer = responseText(value)
    else {
      const choice = value.choices?.[0]
      if (!choice || choice.finish_reason !== 'stop') throw new RelayError('upstream_incomplete')
      answer = choice.message?.content
      completion = value
    }
  }
  if (typeof answer !== 'string' || !answer.trim()) throw new RelayError('empty_answer')
  // Only expose the successful text; upstream metadata can contain internal URLs.
  return { answer, usage: completion?.usage }
}

// Keep the relay deadline below the runtime's 45-second model timeout, while
// allowing structured plans to finish before trying the next provider.
function createAiRelay({providers = [], fetchImpl = globalThis.fetch, attemptTimeoutMs = 30000, totalTimeoutMs = 40000, cooldownMs = 30000} = {}) {
  let entries = normalize(providers), cursor = 0, server = null, baseUrl = null
  const apiKey = randomBytes(32).toString('hex')
  const controllers = new Set()
  async function attempt(provider, body, messages, timeoutMs, requestSignal) {
    if (requestSignal?.aborted) throw new RelayError('request_cancelled')
    const controller = new AbortController()
    controllers.add(controller)
    let timer, onAbort
    const onRequestAbort = () => controller.abort(new RelayError('request_cancelled'))
    requestSignal?.addEventListener('abort', onRequestAbort, {once: true})
    const aborted = new Promise((_, reject) => {
      onAbort = () => reject(controller.signal.reason instanceof RelayError ? controller.signal.reason : new RelayError('request_cancelled'))
      controller.signal.addEventListener('abort', onAbort, {once: true})
    })
    const operation = async () => {
      const headers = providerHeaders(provider)
      const response = await fetchImpl(endpoint(provider), {method: 'POST', headers, body: JSON.stringify(upstreamBody(provider, body, messages)), signal: controller.signal, redirect: 'error'})
      if (!response.ok) throw await upstreamHttpError(response)
      return decodeResponse(await readLimited(response), response.headers.get('content-type') || '', provider.apiMode)
    }
    try {
      timer = setTimeout(() => controller.abort(new RelayError('timeout')), Math.max(1, timeoutMs))
      return await Promise.race([operation(), aborted])
    } catch (error) {
      if (requestSignal?.aborted) throw new RelayError('request_cancelled')
      if (error instanceof RelayError) throw error
      if (controller.signal.aborted) throw controller.signal.reason instanceof RelayError ? controller.signal.reason : new RelayError('request_cancelled')
      throw new RelayError('connection_failed')
    } finally {
      clearTimeout(timer); requestSignal?.removeEventListener('abort', onRequestAbort)
      controller.signal.removeEventListener('abort', onAbort)
      controller.abort(); controllers.delete(controller)
    }
  }

  async function complete(body, requestSignal) {
    const messages = validateRequest(body)
    // Keep a generation snapshot: edits cannot alter an in-flight request or its counters.
    const generation = entries, enabled = generation.filter(e => e.provider.enabled)
    if (!enabled.length) throw new RelayError('no_enabled_providers')
    if (enabled.every(e => e.cooldownUntil > Date.now())) throw new RelayError('all_providers_cooling_down')
    const start = enabled.length ? cursor++ % enabled.length : 0
    const candidates = enabled.slice(start).concat(enabled.slice(0, start))
    const deadline = Date.now() + totalTimeoutMs
    for (const entry of candidates) {
      if (requestSignal?.aborted) throw new RelayError('request_cancelled')
      if (entry.cooldownUntil > Date.now() || Date.now() >= deadline) continue
      const began = Date.now()
      entry.requests++
      try {
        const result = await attempt(entry.provider, body, messages, Math.min(attemptTimeoutMs, deadline - Date.now()), requestSignal)
        entry.successes++; entry.lastError = null; entry.lastReason = null; entry.cooldownUntil = 0; entry.lastLatencyMs = Date.now() - began
        return { ...result, model: entry.provider.model }
      } catch (error) {
        if (error.code === 'request_cancelled' || requestSignal?.aborted) throw new RelayError('request_cancelled')
        entry.failures++; entry.lastError = error.code || 'connection_failed'; entry.lastReason = error.reason || null; entry.cooldownUntil = Date.now() + cooldownMs; entry.lastLatencyMs = Date.now() - began
      }
    }
    throw new RelayError('all_providers_unavailable')
  }

  function sendError(res, status, code) {
    if (!res.destroyed && !res.headersSent) { res.writeHead(status, {'Content-Type': 'application/json'}); res.end(JSON.stringify({error: {type: 'relay_error', code, message: code}})) }
  }

  async function handle(req, res) {
    const actual = Buffer.from(req.headers.authorization || ''), expected = Buffer.from(`Bearer ${apiKey}`)
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) { req.resume(); sendError(res, 401, 'unauthorized'); return }
    if (req.method !== 'POST' || req.url !== '/v1/chat/completions') { req.resume(); sendError(res, 404, 'not_found'); return }
    const requestController = new AbortController()
    const onClose = () => { if (!res.writableEnded) requestController.abort() }
    res.once('close', onClose)
    try {
      const buffers = []; let size = 0
      for await (const chunk of req) {
        size += chunk.length
        if (size > MAX_BODY) { sendError(res, 413, 'request_too_large'); req.resume(); return }
        buffers.push(chunk)
      }
      let body
      try { body = JSON.parse(Buffer.concat(buffers).toString('utf8')) } catch { sendError(res, 400, 'invalid_json'); return }
      const result = await complete(body, requestController.signal)
      if (requestController.signal.aborted || res.destroyed) return
      const common = {id: `chatcmpl-relay-${randomBytes(8).toString('hex')}`, created: Math.floor(Date.now() / 1000), model: result.model}
      if (body.stream === true) {
        res.writeHead(200, {'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache'})
        res.write(`data: ${JSON.stringify({...common, object: 'chat.completion.chunk', choices: [{index: 0, delta: {role: 'assistant', content: result.answer}, finish_reason: null}]})}\n\n`)
        res.write(`data: ${JSON.stringify({...common, object: 'chat.completion.chunk', choices: [{index: 0, delta: {}, finish_reason: 'stop'}]})}\n\n`)
        res.end('data: [DONE]\n\n')
      } else {
        res.writeHead(200, {'Content-Type': 'application/json'})
        res.end(JSON.stringify({...common, object: 'chat.completion', choices: [{index: 0, message: {role: 'assistant', content: result.answer}, finish_reason: 'stop'}], ...(result.usage ? {usage: result.usage} : {})}))
      }
    } catch (error) {
      if (error.code === 'request_cancelled') return
      const code = ['text_messages_required', 'no_enabled_providers', 'all_providers_cooling_down'].includes(error.code) ? error.code : 'all_providers_unavailable'
      sendError(res, code === 'text_messages_required' ? 400 : 503, code)
    } finally { res.removeListener('close', onClose) }
  }

  return {
    async start() {
      if (!server) {
        server = http.createServer((req, res) => { void handle(req, res) })
        server.requestTimeout = 15000; server.headersTimeout = 10000
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
        baseUrl = `http://127.0.0.1:${server.address().port}/v1`
      }
      return {baseUrl, apiKey}
    },
    setProviders(providers) { entries = normalize(providers); cursor = 0 },
    status() { return {running: Boolean(server?.listening), providers: entries.map(({provider, ...stats}) => ({id: provider.id, name: provider.name, enabled: provider.enabled, ...stats}))} },
    async testProvider(provider, prompt = '你好，请简短介绍自己。') {
      const began = Date.now()
      try {
        if (typeof prompt !== 'string' || !prompt.trim() || prompt.length > 4000) throw new RelayError('invalid_test_prompt')
        const entry = normalize([provider])[0]
        const body = {messages: [{role: 'user', content: prompt.trim()}], max_tokens: 512}
        const result = await attempt(entry.provider, body, body.messages, attemptTimeoutMs)
        return {ok: true, message: '连接成功', latencyMs: Date.now() - began, reply: result.answer}
      } catch (error) { return {ok: false, message: error.code || 'invalid_provider', reason: error.reason || null, latencyMs: Date.now() - began} }
    },
    async close() {
      for (const controller of controllers) controller.abort()
      if (server) {
        const closing = server; server = null; baseUrl = null
        await new Promise(resolve => { closing.close(resolve); closing.closeAllConnections?.() })
      }
    },
  }
}

module.exports = {createAiRelay, listProviderModels}
