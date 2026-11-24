'use strict'
// 第401轮：桌面凭据“变更型”操作必须区分首次设置与已配置后的重新验证。
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const { credentialMutationPolicy } = require('../electron/desktop-credential-policy.cjs')

let passed = 0
async function test(name, fn) { await fn(); passed++; console.log(`PASS ${name}`) }

async function main() {
  await test('first-time setup is allowed without Hello', () => {
    assert.deepEqual(credentialMutationPolicy({configured: false}), {allowed: true, mode: 'first-time'})
    assert.deepEqual(credentialMutationPolicy({}), {allowed: true, mode: 'first-time'})
  })
  await test('configured account requires verified Hello', () => {
    const denied = credentialMutationPolicy({configured: true})
    assert.equal(denied.allowed, false)
    assert.equal(denied.code, 'credential_reauthentication_required')
    const allowed = credentialMutationPolicy({configured: true, helloVerified: true})
    assert.deepEqual(allowed, {allowed: true, mode: 'reauthenticated'})
  })
  await test('non-boolean Hello results never unlock a configured account', () => {
    for (const value of ['true', 1, {}, null, undefined]) {
      assert.equal(credentialMutationPolicy({configured: true, helloVerified: value}).allowed, false)
    }
  })

  // 静态接线检查：三个会改写凭据的 IPC 必须在执行变更前调用统一门禁。
  const main = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.cjs'), 'utf8')
  const handler = (name) => {
    const start = main.indexOf(`handleRendererIpc("${name}"`)
    assert.notEqual(start, -1, `${name} handler missing`)
    const end = main.indexOf('handleRendererIpc(', start + 1)
    return main.slice(start, end === -1 ? undefined : end)
  }
  await test('bind handler authenticates before rebinding', () => {
    const block = handler('toolbox:bind-desktop-login')
    const gate = block.indexOf('requireCredentialMutationReauthentication("bind")')
    const mutate = block.indexOf('markDesktopCredentialBinding()')
    assert.ok(gate !== -1 && mutate !== -1 && gate < mutate)
    assert.match(block, /async \(event\)/)
  })
  await test('generate handler authenticates before resetting the admin credential', () => {
    const block = handler('toolbox:generate-desktop-login')
    const gate = block.indexOf('requireCredentialMutationReauthentication("generate")')
    const mutate = block.indexOf('updateDesktopAdminPassword')
    assert.ok(gate !== -1 && mutate !== -1 && gate < mutate)
  })
  await test('init handler authenticates before writing a custom credential', () => {
    const block = handler('toolbox:init-desktop-login')
    const gate = block.indexOf('requireCredentialMutationReauthentication("init")')
    const mutate = block.indexOf('updateDesktopAdminPassword')
    assert.ok(gate !== -1 && mutate !== -1 && gate < mutate)
  })
  await test('gate only unlocks configured accounts through a verified Hello result', () => {
    const gateStart = main.indexOf('async function requireCredentialMutationReauthentication')
    const gateEnd = main.indexOf('\n}', gateStart)
    const gate = main.slice(gateStart, gateEnd)
    assert.match(gate, /desktopCredentialState\(\)/)
    assert.match(gate, /verifyWindowsHello\(\)/)
    assert.match(gate, /helloVerified = hello\.verified === true/)
    assert.match(gate, /credentialMutationPolicy\(\{ configured, helloVerified \}\)/)
  })
  console.log(`${passed} desktop credential policy tests passed`)
}

main().catch(error => { console.error(error); process.exitCode = 1 })

