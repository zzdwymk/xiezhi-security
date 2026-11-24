'use strict'
// 第402轮：AI 线路超时/上限契约漂移守卫。
// 界面文案（src/utils/aiRelayContract.ts）必须与主进程实现（electron/ai-relay.cjs）一致，
// 也必须被组件真正引用，而不是各写一份字面量。
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const { AI_RELAY_DEFAULTS } = require('../electron/ai-relay.cjs')

const root = path.join(__dirname, '..')
const contractSource = fs.readFileSync(path.join(root, 'src', 'utils', 'aiRelayContract.ts'), 'utf8')
const component = fs.readFileSync(path.join(root, 'src', 'components', 'AiRelaySettings.vue'), 'utf8')

const numberFor = (name) => {
  const match = contractSource.match(new RegExp(`export const ${name}\\s*=\\s*(\\d+)`))
  assert.ok(match, `contract constant ${name} missing`)
  return Number(match[1])
}

let passed = 0
async function test(name, fn) { await fn(); passed++; console.log(`PASS ${name}`) }

async function main() {
  await test('UI contract matches relay defaults exactly', () => {
    assert.equal(numberFor('AI_RELAY_ATTEMPT_TIMEOUT_SECONDS') * 1000, AI_RELAY_DEFAULTS.attemptTimeoutMs)
    assert.equal(numberFor('AI_RELAY_TOTAL_TIMEOUT_SECONDS') * 1000, AI_RELAY_DEFAULTS.totalTimeoutMs)
    assert.equal(numberFor('AI_RELAY_COOLDOWN_SECONDS') * 1000, AI_RELAY_DEFAULTS.cooldownMs)
    assert.equal(numberFor('AI_RELAY_MAX_PROMPT_CHARS'), AI_RELAY_DEFAULTS.maxPromptChars)
    assert.equal(numberFor('AI_RELAY_MAX_PROVIDERS'), AI_RELAY_DEFAULTS.maxProviders)
  })
  await test('relay defaults and contract stay within sane bounds', () => {
    assert.ok(AI_RELAY_DEFAULTS.attemptTimeoutMs > 0 && AI_RELAY_DEFAULTS.attemptTimeoutMs < 600000)
    assert.ok(AI_RELAY_DEFAULTS.totalTimeoutMs >= AI_RELAY_DEFAULTS.attemptTimeoutMs)
    assert.ok(AI_RELAY_DEFAULTS.cooldownMs >= 0 && AI_RELAY_DEFAULTS.cooldownMs <= 60000)
    assert.ok(AI_RELAY_DEFAULTS.maxPromptChars >= 1000 && AI_RELAY_DEFAULTS.maxPromptChars <= 32000)
    assert.ok(AI_RELAY_DEFAULTS.maxProviders >= 1 && AI_RELAY_DEFAULTS.maxProviders <= 16)
  })
  await test('component uses the shared helper instead of stale literals', () => {
    assert.match(component, /relayDeadlineHelp\(\)/)
    assert.match(component, /AI_RELAY_MAX_PROMPT_CHARS/)
    assert.match(component, /AI_RELAY_MAX_PROVIDERS/)
    assert.doesNotMatch(component, /单线路最多\s*30\s*秒/)
    assert.doesNotMatch(component, /总计最多\s*40\s*秒/)
    assert.doesNotMatch(component, /失败冷却\s*30\s*秒/)
    assert.doesNotMatch(component, /最多\s*16\s*条线路/)
    assert.doesNotMatch(component, /maxlength="4000"/)
  })
  await test('test success message no longer claims a complete answer for rescued text', () => {
    assert.doesNotMatch(component, /已收到完整模型回答/)
    assert.match(component, /已收到模型回答/)
  })
  await test('invalid_request from relay has a user-facing explanation', () => {
    assert.match(component, /invalid_request:/)
  })
  await test('help text renders the actual default numbers', () => {
    const help = contractSource.match(/export function relayDeadlineHelp\(\): string \{([\s\S]*?)\n\}/)
    assert.ok(help)
    assert.match(help[1], /AI_RELAY_ATTEMPT_TIMEOUT_SECONDS/)
    assert.match(help[1], /AI_RELAY_TOTAL_TIMEOUT_SECONDS/)
    assert.match(help[1], /AI_RELAY_COOLDOWN_SECONDS/)
    assert.match(help[1], /AI_RELAY_MAX_PROVIDERS/)
  })
  console.log(`${passed} AI relay contract tests passed`)
}

main().catch(error => { console.error(error); process.exitCode = 1 })