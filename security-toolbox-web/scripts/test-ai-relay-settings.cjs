"use strict";
const assert = require("node:assert/strict");
const { normalizeRelaySettings: normalize, publicRelaySettings, resolveRelayProviders, resolveModelDiscoveryProvider } =
  require("../electron/ai-relay-settings.cjs");

// Opaque test vault: never confuse reversible test encoding with production encryption.
const vault = new Map();
const crypto = {
  encrypt(value) { const token = `cipher-${vault.size}`; vault.set(token, value); return token; },
  decrypt(value) { if (!vault.has(value)) throw new Error("private backend detail"); return vault.get(value); },
};
const base = { id: "one", name: "主线路", baseUrl: "https://relay.example/v1", model: "model-a", apiKey: "test-secret" };
const settings = (provider = base, enabled = true) => ({ enabled, providers: [provider] });
const stored = normalize(settings(), {}, crypto);
assert.deepEqual(normalize(), { enabled: false, providers: [] });
assert.equal(stored.providers[0].baseUrl, "https://relay.example/v1");
assert.equal(stored.providers[0].apiMode, "chat_completions");
assert.equal(stored.providers[0].codexHeaders, false);
assert.equal(stored.providers[0].enabled, true);
assert.ok(!JSON.stringify(stored).includes("test-secret"));
assert.ok(!Object.hasOwn(stored.providers[0], "apiKey"));

const publicSettings = publicRelaySettings({ ...stored, providers: [{ ...stored.providers[0], apiKey: "leaked" }] });
assert.equal(publicSettings.providers[0].hasApiKey, true);
assert.equal(publicSettings.providers[0].keyHint, "已保存");
assert.ok(!Object.hasOwn(publicSettings.providers[0], "apiKey"));
assert.ok(!Object.hasOwn(publicSettings.providers[0], "encryptedApiKey"));
assert.ok(!JSON.stringify(publicSettings).includes("cipher-"));
assert.deepEqual(publicRelaySettings(), { enabled: false, providers: [] });
assert.equal(resolveRelayProviders(stored, crypto)[0].apiKey, "test-secret");
assert.ok(!Object.hasOwn(resolveRelayProviders(stored, crypto)[0], "encryptedApiKey"));

const retained = normalize(settings({ ...base, apiKey: "", model: "model-b", apiMode: "responses" }), stored, crypto);
assert.equal(retained.providers[0].encryptedApiKey, stored.providers[0].encryptedApiKey);
assert.equal(resolveRelayProviders(retained, crypto)[0].apiKey, "test-secret");
const testOnly = normalize(settings({ ...base, apiKey: "" }, false), stored, crypto);
assert.equal(testOnly.enabled, false);
assert.equal(testOnly.providers[0].encryptedApiKey, stored.providers[0].encryptedApiKey);
assert.equal(stored.enabled, true);
assert.equal(stored.providers[0].model, "model-a");

for (const suffix of ["/v1", "/v1/", "/v1/chat/completions", "/v1/responses/"]) {
  assert.equal(normalize(settings({ ...base, baseUrl: `https://relay.example${suffix}`, apiKey: "" }), stored, crypto)
    .providers[0].encryptedApiKey, stored.providers[0].encryptedApiKey);
}
assert.equal(normalize(settings({ ...base, baseUrl: "https://relay.example/api/v1/responses" }), {}, crypto)
  .providers[0].baseUrl, "https://relay.example/api/v1");
for (const baseUrl of ["https://other.example", "https://relay.example/another", "http://localhost:1234"]) {
  assert.throws(() => normalize(settings({ ...base, baseUrl, apiKey: "" }), stored, crypto), /地址已改变/);
}
const replaced = normalize(settings({ ...base, baseUrl: "https://other.example", apiKey: "new-secret" }), stored, crypto);
assert.equal(resolveRelayProviders(replaced, crypto)[0].apiKey, "new-secret");
assert.throws(() => normalize(settings({ ...base, id: "new-id", apiKey: "" }), stored, crypto), /必须提供密钥/);

for (const baseUrl of ["http://localhost:8080/v1", "http://127.0.0.1:8080", "http://[::1]:8080", "https://localhost"]) {
  const anonymous = normalize(settings({ ...base, baseUrl, apiKey: "" }), {}, crypto);
  assert.equal(anonymous.providers[0].encryptedApiKey, "");
  assert.equal(publicRelaySettings(anonymous).providers[0].hasApiKey, false);
  assert.equal(resolveRelayProviders(anonymous, crypto)[0].apiKey, "");
}
for (const baseUrl of ["http://remote.example", "ftp://relay.example", "https://u:p@relay.example", "https://@relay.example",
  "https://relay.example?", "https://relay.example?secret=private", "https://relay.example#", "https://relay.example#secret", "invalid"]) {
  assert.throws(() => normalize(settings({ ...base, baseUrl }), {}, crypto), /地址|HTTPS/);
}
for (const apiKey of ["bad\rkey", "bad\nkey", "bad\0key", "x".repeat(8193), 123, null]) {
  assert.throws(() => normalize(settings({ ...base, apiKey }), {}, crypto), /密钥格式无效/);
}
assert.doesNotThrow(() => normalize(settings({ ...base, apiKey: "x".repeat(8192) }), {}, crypto));
assert.throws(() => normalize(settings(), {}, { encrypt() { throw new Error("secret"); } }), /^Error: 无法安全保存线路密钥$/);
assert.throws(() => resolveRelayProviders(stored, { decrypt() { throw new Error("secret"); } }), /^Error: 无法读取线路密钥，请重新保存密钥$/);
assert.throws(() => resolveRelayProviders(stored, { decrypt() { return "bad\nkey"; } }), /无法读取线路密钥/);

assert.throws(() => normalize({ enabled: true }), /至少一条/);
assert.throws(() => normalize(settings({ ...base, enabled: false }), {}, crypto), /至少一条/);
assert.throws(() => normalize({ providers: [base, base] }, {}, crypto), /不能重复/);
assert.throws(() => normalize({ providers: Array(17).fill(base) }, {}, crypto), /16/);
assert.equal(normalize({ providers: Array.from({ length: 16 }, (_, i) => ({ ...base, id: `p${i}` })) }, {}, crypto).providers.length, 16);
for (const [field, max] of [["id", 128], ["name", 80], ["model", 160]]) {
  assert.doesNotThrow(() => normalize(settings({ ...base, [field]: "x".repeat(max) }), {}, crypto));
  assert.throws(() => normalize(settings({ ...base, [field]: "x".repeat(max + 1) }), {}, crypto), /格式无效/);
  assert.throws(() => normalize(settings({ ...base, [field]: " " }), {}, crypto), /不能为空/);
}
assert.throws(() => normalize(settings({ ...base, apiMode: "invalid" }), {}, crypto), /接口模式无效/);
assert.throws(() => normalize(settings({ ...base, codexHeaders: "true" }), {}, crypto), /格式无效/);
assert.throws(() => normalize({ enabled: "true" }), /格式无效/);
const snapshot = JSON.stringify(stored);
const codex = normalize(settings({ ...base, apiMode: "chat_completions", codexHeaders: true }), {}, crypto);
assert.equal(codex.providers[0].apiMode, "responses");
assert.equal(publicRelaySettings({providers:[{...stored.providers[0],codexHeaders:true}]}).providers[0].apiMode, "responses");
const discoveryDraft = { ...base, model: "", apiKey: "" };
assert.equal(resolveModelDiscoveryProvider(discoveryDraft, stored, crypto).apiKey, "test-secret");
assert.equal(discoveryDraft.model, "");
assert.equal(JSON.stringify(stored), snapshot);
assert.throws(() => resolveModelDiscoveryProvider({ ...discoveryDraft, baseUrl: "https://changed.example" }, stored, crypto), /地址已改变/);
assert.equal(resolveModelDiscoveryProvider({ ...discoveryDraft, baseUrl: "https://changed.example", apiKey: "new-secret" }, stored, crypto).apiKey, "new-secret");
assert.throws(() => resolveModelDiscoveryProvider(null, stored, crypto), /格式无效/);
console.log("AI relay settings tests passed");
