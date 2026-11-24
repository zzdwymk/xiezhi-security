'use strict'
// 第403轮：API 基址信任边界。渲染进程会自动附加 Bearer Token，
// 因此 ?backend= 只能指向本机回环且路径为 /api；其余一律回退同源 /api。
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const ts = require('typescript')

const file = path.join(__dirname, '..', 'src', 'utils', 'apiBaseUrl.ts')
const compiled = ts.transpileModule(fs.readFileSync(file, 'utf8'), {
  compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020},
}).outputText
const sandbox = {exports: {}, module: {exports: {}}, URL, String}
sandbox.module.exports = sandbox.exports
new Function('exports', 'module', 'URL', 'String', compiled)(sandbox.exports, sandbox.module, URL, String)
const {sanitizeApiBaseUrl} = sandbox.module.exports

let passed = 0
async function test(name, fn) { await fn(); passed++; console.log(`PASS ${name}`) }

async function main() {
  await test('accepts loopback backend with /api path', () => {
    assert.equal(sanitizeApiBaseUrl('http://127.0.0.1:18080/api'), 'http://127.0.0.1:18080/api')
    assert.equal(sanitizeApiBaseUrl('http://localhost:8080/api/'), 'http://localhost:8080/api')
    assert.equal(sanitizeApiBaseUrl('https://127.0.0.1:8443/api'), 'https://127.0.0.1:8443/api')
  })
  await test('rejects non-loopback hosts to prevent token exfiltration', () => {
    for (const raw of [
      'https://evil.example/api',
      'http://192.168.222.155:8080/api',
      'http://10.0.0.5/api',
      'http://169.254.169.254/api',
      'http://[2001:db8::1]/api',
    ]) assert.equal(sanitizeApiBaseUrl(raw), '/api', raw)
  })
  await test('rejects credentials, query, fragment and non-api paths', () => {
    for (const raw of [
      'http://user:pw@127.0.0.1:18080/api',
      'http://127.0.0.1:18080/api?token=x',
      'http://127.0.0.1:18080/api#frag',
      'http://127.0.0.1:18080/admin',
      'file:///C:/secret/api',
      'javascript:alert(1)',
      'ftp://127.0.0.1/api',
    ]) assert.equal(sanitizeApiBaseUrl(raw), '/api', raw)
  })
  await test('empty or missing backend falls back to same-origin /api', () => {
    for (const raw of [null, undefined, '', '   ']) assert.equal(sanitizeApiBaseUrl(raw), '/api')
  })
  await test('relative /api keeps working for browser mode', () => {
    assert.equal(sanitizeApiBaseUrl('/api'), 'http://127.0.0.1/api')
  })
  await test('client actually imports the sanitizer instead of trusting the query directly', () => {
    const client = fs.readFileSync(path.join(__dirname, '..', 'src', 'apiClient.ts'), 'utf8')
    assert.match(client, /import \{ sanitizeApiBaseUrl \} from "\.\/utils\/apiBaseUrl"/)
    assert.match(client, /sanitizeApiBaseUrl\(\s*query\.get\("backend"\)/)
    assert.doesNotMatch(client, /export const apiBaseUrl\s*=\s*\n?\s*query\.get\("backend"\)/)
  })
  console.log(`${passed} API base URL tests passed`)
}

main().catch(error => { console.error(error); process.exitCode = 1 })