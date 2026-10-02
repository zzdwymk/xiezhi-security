'use strict'

// All traffic is loopback. No desktop state, real credentials or external
// providers are read. Keep the Python interpreter isolated from pytest imports.
const assert = require('node:assert/strict')
const http = require('node:http')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs/promises')
const {spawn} = require('node:child_process')
const {createAiRelay} = require('../electron/ai-relay.cjs')

// Set AI_RELAY_TEST_PYTHON when the runtime dependencies live in a virtual environment.
const python = process.env.AI_RELAY_TEST_PYTHON || 'python'
const runtimeRoot = path.resolve(__dirname, '../../ai-runtime')
const probe = path.join(__dirname, 'ai-relay-runtime-probe.py')
const route = {intent: 'GENERAL_QA', needsRetrieval: false, publicReasonCode: 'GENERAL_KNOWLEDGE'}
const grounded = {summary: 'HTTP headers', answer: 'HTTP response headers describe the response.',
  intent: 'answer', knowledgeMode: 'GENERAL', evidenceRefs: [], actions: []}

async function startServer(handler) {
  const server = http.createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch(() => {
      if (!res.headersSent) res.writeHead(500)
      res.end('fixture_error')
    })
  })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
  return {server, baseUrl: `http://127.0.0.1:${server.address().port}/v1`}
}

async function closeServer(server) {
  await new Promise(resolve => { server.close(resolve); server.closeAllConnections() })
}

async function runProbe(connection, dataDir) {
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !key.startsWith('AI_RUNTIME_') && !key.startsWith('OPENAI_') && !key.startsWith('AI_AGENT_')))
  const env = {...inherited, PYTHONPATH: runtimeRoot, PYTHONUTF8: '1',
    AI_RUNTIME_LLM_ENABLED: 'true', AI_RUNTIME_PROXY_MODE: 'false',
    AI_RUNTIME_API_MODE: 'chat_completions', AI_RUNTIME_MODEL: 'xiezhi-relay',
    AI_RUNTIME_API_KEY: connection.apiKey, AI_RUNTIME_BASE_URL: connection.baseUrl,
    AI_RUNTIME_DATA_DIR: dataDir, AI_RUNTIME_LLM_TIMEOUT_SECONDS: '10'}
  return new Promise((resolve, reject) => {
    const child = spawn(python, [probe], {cwd: runtimeRoot, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']})
    let stdout = '', stderr = ''
    const timer = setTimeout(() => { child.kill(); reject(new Error('Python integration probe timed out')) }, 30000)
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.on('data', chunk => { stderr += chunk })
    child.once('error', error => { clearTimeout(timer); reject(error) })
    child.once('close', code => {
      clearTimeout(timer)
      // Defense in depth: never print the ephemeral relay credential on failure.
      const safeError = stderr.split(connection.apiKey).join('[REDACTED]')
      if (code !== 0) reject(new Error(`Python integration probe failed (${code}): ${safeError}`))
      else { try { resolve(JSON.parse(stdout)) } catch { reject(new Error('Invalid Python probe result')) } }
    })
  })
}

async function scenario(apiMode) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-relay-runtime-'))
  let a, b, relay
  let aCalls = 0, bCalls = 0
  const requests = []
  try {
    a = await startServer(async (req, res) => {
      aCalls++
      for await (const _ of req) { /* drain the request */ }
      res.writeHead(500, {'Content-Type': 'application/json'})
      res.end(JSON.stringify({error: {message: 'Simulated capacity failure'}}))
    })
    b = await startServer(async (req, res) => {
      bCalls++
      let raw = ''
      for await (const chunk of req) raw += chunk
      const body = JSON.parse(raw)
      requests.push({url: req.url, authorization: req.headers.authorization, body})
      const instructions = apiMode === 'responses' ? body.instructions : body.messages.find(m => m.role === 'system')?.content
      const result = instructions?.includes('grounded planner') ? grounded : route
      if (apiMode === 'responses') {
        const event = {type: 'response.completed', response: {status: 'completed',
          output: [{type: 'message', content: [{type: 'output_text', text: JSON.stringify(result)}]}]}}
        res.writeHead(200, {'Content-Type': 'text/event-stream'})
        res.end(`event: response.completed\ndata: ${JSON.stringify(event)}\n\n`)
      } else {
        res.writeHead(200, {'Content-Type': 'application/json'})
        res.end(JSON.stringify({id: 'fixture-completion', object: 'chat.completion', model: 'fixture-b',
          choices: [{index: 0, message: {role: 'assistant', content: JSON.stringify(result)}, finish_reason: 'stop'}]}))
      }
    })
    relay = createAiRelay({providers: [
      {id: 'a', baseUrl: a.baseUrl, model: 'fixture-a', apiKey: 'fixture-a-token'},
      {id: 'b', baseUrl: b.baseUrl, model: 'fixture-b', apiKey: 'fixture-b-token', apiMode},
    ], cooldownMs: 60000})
    const connection = await relay.start()
    assert.deepEqual(await runProbe(connection, dataDir), {ok: true, modelCalls: 3, source: 'langchain-grounded'})
    assert.equal(aCalls, 1)
    assert.equal(bCalls, 3)
    const status = relay.status()
    assert.equal(status.providers[0].failures, 1)
    assert.equal(status.providers[0].lastError, 'http_500')
    assert.ok(status.providers[0].cooldownUntil > Date.now())
    assert.equal(status.providers[1].successes, 3)
    for (const request of requests) {
      assert.equal(request.url, apiMode === 'responses' ? '/v1/responses' : '/v1/chat/completions')
      assert.equal(request.authorization, 'Bearer fixture-b-token')
      assert.equal(request.body.model, 'fixture-b')
      if (apiMode === 'responses') {
        assert.equal(request.body.store, false)
        assert.equal(request.body.stream, true)
        assert.equal(typeof request.body.instructions, 'string')
      }
    }
    console.log(`PASS real Python runtime -> Node relay -> ${apiMode}: A HTTP 500, B answers route + grounded, A cooldown honored`)
  } finally {
    if (relay) await relay.close()
    if (a) await closeServer(a.server)
    if (b) await closeServer(b.server)
    await fs.rm(dataDir, {recursive: true, force: true})
  }
}

async function main() {
  await scenario('chat_completions')
  await scenario('responses')
}
main().catch(error => { console.error(error.message); process.exitCode = 1 })
