const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { UserFacingError, publicErrorMessage } = require('../electron/public-error.cjs');
const { resolveRelayProviders } = require('../electron/ai-relay-settings.cjs');

// Execute the actual boot catch with in-memory dependencies. No Electron,
// windows, services, real profile files, keys, network or processes are used.
const source = fs.readFileSync(path.join(__dirname, '../electron/main.cjs'), 'utf8');
const start = source.indexOf('async function boot() {');
const end = source.indexOf('\nif (hasSingleInstanceLock)', start);
assert.ok(start >= 0 && end > start, 'boot function boundary must exist');
const bootSource = source.slice(start, end);
const fallback = '本地服务启动失败，请查看桌面日志确认原因，排除问题后重新启动桌面程序。';

async function failureAtBoot(error, options = {}) {
  const updates = [], diagnostics = [], cleanup = [];
  const context = vm.createContext({
    UserFacingError, publicErrorMessage,
    configuredThemeMode: () => 'system', applyThemeMode: () => {},
    createStartupWindow: () => {},
    updateStartup: (...args) => updates.push(args),
    ensureDesktopCredentials: () => { if (!options.atRelay) throw error; },
    resolveJava: () => 'test-java', resolveServerJar: () => 'test.jar',
    findFreePort: async () => 12345,
    prepareDesktopMitmCaMigration: () => 'test-migration',
    allocateAiRuntimeSlot: async () => { throw error; },
    stopAiRuntime: () => cleanup.push('ai'),
    stopBackend: async () => cleanup.push('backend'),
    rollbackDesktopMitmCaMigration: migration => {
      cleanup.push(['rollback', migration]);
      if (options.rollbackError) throw options.rollbackError;
    },
    writeDesktopStartupDiagnostic: (...args) => diagnostics.push(args),
  });
  vm.runInContext(bootSource, context, { filename: 'main.cjs:boot' });
  await context.boot();
  const final = updates.at(-1);
  assert.equal(final[0], '启动失败');
  assert.equal(final[1], '无法进入工具工作区。');
  assert.deepEqual(cleanup.slice(0, 2), ['ai', 'backend']);
  assert.equal(cleanup[2][0], 'rollback');
  assert.equal(diagnostics[0][0], 'boot');
  assert.equal(diagnostics[0][1], error, 'diagnostics retain the original error');
  return { message: final[2], diagnostics };
}

(async () => {
  // Reproduce the production relay validator's loss of UserFacingError type.
  let relayFailure;
  const saved = { enabled: true, providers: [{
    id: 'fixture', name: 'fixture', model: 'fixture-model',
    baseUrl: 'https://provider.invalid', encryptedApiKey: 'fixture-ciphertext',
  }] };
  try {
    resolveRelayProviders(saved, { decrypt() { throw new Error('crypto-secret-fixture'); } });
  } catch (error) { relayFailure = error; }
  assert.ok(relayFailure);
  assert.equal(relayFailure.message, '无法读取线路密钥，请重新保存密钥');
  assert.ok(!(relayFailure instanceof UserFacingError));
  const relay = await failureAtBoot(relayFailure, { atRelay: true });
  assert.match(relay.message, /AI 中转线路密钥无法读取/);
  assert.match(relay.message, /Windows 用户.*配置备份.*重新启动/);
  assert.doesNotMatch(relay.message, /Java|crypto-secret|fixture-ciphertext|provider\.invalid/);

  const trustedMessage = '本地 PostgreSQL 未能启动，请检查数据库配置。';
  assert.equal((await failureAtBoot(new UserFacingError(trustedMessage))).message, trustedMessage);
  assert.equal((await failureAtBoot(new UserFacingError('  '))).message, fallback);
  const sensitive = new Error('connect failed https://user:secret@provider.invalid/?api_key=secret');
  assert.equal((await failureAtBoot(sensitive)).message, fallback);
  assert.equal((await failureAtBoot({ message: 'token=secret' })).message, fallback);
  assert.equal((await failureAtBoot(null)).message, fallback);
  const recoveryError = new Error('recovery-secret');
  const recovered = await failureAtBoot(relayFailure, { atRelay: true, rollbackError: recoveryError });
  assert.equal(recovered.message, relay.message, 'recovery failure does not overwrite primary attribution');
  assert.equal(recovered.diagnostics[1][0], 'mitm-ca-recovery');
  assert.equal(recovered.diagnostics[1][1], recoveryError);
  assert.doesNotMatch(recovered.message, /recovery-secret/);
  console.log('PASS: 7 boot failure scenarios; trusted attribution, safe fallback and cleanup preserved');
})().catch(error => { console.error(error); process.exitCode = 1; });
