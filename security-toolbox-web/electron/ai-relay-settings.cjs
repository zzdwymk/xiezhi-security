"use strict";

function fail(message) {
  throw new Error(message);
}

function text(value, max, label) {
  if (typeof value !== "string" || value.length > max || /[\x00-\x1f\x7f]/.test(value)) {
    fail(`${label}格式无效`);
  }
  const result = value.trim();
  if (!result) fail(`${label}不能为空`);
  return result;
}

function boolean(value, fallback, label) {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") fail(`${label}格式无效`);
  return value;
}

function isLoopback(url) {
  return url.hostname === "localhost" || url.hostname === "[::1]" ||
    /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(url.hostname);
}

function normalizeBaseUrl(value) {
  const input = text(value, 2048, "线路地址");
  let url;
  try { url = new URL(input); } catch { fail("线路地址无效"); }
  if (url.username || url.password || /^[a-z]+:\/\/[^/]*@/i.test(input) || input.includes("?") || input.includes("#") ||
      !["http:", "https:"].includes(url.protocol)) {
    fail("线路地址必须为不含账户信息、查询参数或片段的 HTTP(S) 地址");
  }
  if (url.protocol === "http:" && !isLoopback(url)) {
    fail("非本机线路必须使用 HTTPS");
  }
  url.pathname = url.pathname.replace(/\/+$/, "")
    .replace(/\/(?:chat\/completions|responses)$/, "");
  return url.toString().replace(/\/+$/, "");
}

function normalizeRelaySettings(payload, existingStored = {}, crypto = {}) {
  if (payload == null) payload = {};
  if (typeof payload !== "object" || Array.isArray(payload)) fail("中转站设置格式无效");
  const enabled = boolean(payload.enabled, false, "中转站开关");
  const providers = payload.providers === undefined ? [] : payload.providers;
  if (!Array.isArray(providers) || providers.length > 16) fail("中转线路最多为 16 条");
  const existingProviders = Array.isArray(existingStored?.providers) ? existingStored.providers : [];
  const ids = new Set();
  const normalized = providers.map((provider) => {
    if (!provider || typeof provider !== "object" || Array.isArray(provider)) fail("线路设置格式无效");
    const id = text(provider.id, 128, "线路标识");
    if (ids.has(id)) fail("线路标识不能重复");
    ids.add(id);
    const name = text(provider.name, 80, "线路名称");
    const model = text(provider.model, 160, "模型名称");
    const baseUrl = normalizeBaseUrl(provider.baseUrl);
    const apiMode = provider.apiMode === undefined ? "chat_completions" : provider.apiMode;
    if (!["chat_completions", "responses"].includes(apiMode)) fail("线路接口模式无效");
    const codexHeaders = boolean(provider.codexHeaders, false, "线路兼容请求头开关");
    const providerEnabled = boolean(provider.enabled, true, "线路开关");
    const rawKey = provider.apiKey === undefined ? "" : provider.apiKey;
    if (typeof rawKey !== "string" || rawKey.length > 8192 || /[\r\n\x00]/.test(rawKey)) {
      fail("线路密钥格式无效");
    }
    const apiKey = rawKey.trim();
    const existing = existingProviders.find((item) => item?.id === id);
    let encryptedApiKey = "";
    if (apiKey) {
      try {
        encryptedApiKey = crypto.encrypt(apiKey);
        if (typeof encryptedApiKey !== "string" || !encryptedApiKey) throw new Error();
      } catch { fail("无法安全保存线路密钥"); }
    } else if (existing?.encryptedApiKey) {
      if (normalizeBaseUrl(existing.baseUrl) !== baseUrl) {
        fail("线路地址已改变，请重新输入密钥");
      }
      if (typeof existing.encryptedApiKey !== "string") fail("已保存的线路密钥格式无效");
      encryptedApiKey = existing.encryptedApiKey;
    } else if (!isLoopback(new URL(baseUrl))) {
      fail("非本机线路必须提供密钥");
    }
    return { id, name, baseUrl, model, apiMode: codexHeaders ? "responses" : apiMode, codexHeaders, enabled: providerEnabled, encryptedApiKey };
  });
  if (enabled && !normalized.some((provider) => provider.enabled)) {
    fail("启用中转站需要至少一条已启用线路");
  }
  return { enabled, providers: normalized };
}

function publicRelaySettings(stored) {
  return {
    enabled: stored?.enabled === true,
    providers: (Array.isArray(stored?.providers) ? stored.providers : []).map((provider) => ({
      id: provider.id, name: provider.name, baseUrl: provider.baseUrl, model: provider.model,
      apiMode: provider.codexHeaders ? "responses" : provider.apiMode, codexHeaders: provider.codexHeaders, enabled: provider.enabled,
      hasApiKey: Boolean(provider.encryptedApiKey),
      keyHint: provider.encryptedApiKey ? "已保存" : "",
    })),
  };
}

function resolveRelayProviders(stored, crypto = {}) {
  // Revalidate persisted configuration before returning credentials to the relay.
  const validated = normalizeRelaySettings(stored, stored);
  return validated.providers.map(({ encryptedApiKey, ...provider }) => {
    let apiKey = "";
    if (encryptedApiKey) {
      try {
        apiKey = crypto.decrypt(encryptedApiKey);
        if (typeof apiKey !== "string" || !apiKey.trim() || apiKey.length > 8192 || /[\r\n\x00]/.test(apiKey)) {
          throw new Error();
        }
      } catch { fail("无法读取线路密钥，请重新保存密钥"); }
    }
    return { ...provider, apiKey };
  });
}

function resolveModelDiscoveryProvider(payload, existingStored, crypto) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) fail("线路设置格式无效");
  // Discovery needs connection credentials, but no model has been selected yet.
  // The temporary model is validated in memory only and never persisted.
  const draft = { ...payload, model: "model-discovery", name: payload.name || "API" };
  const validated = normalizeRelaySettings({ enabled: false, providers: [draft] }, existingStored, crypto);
  const [provider] = resolveRelayProviders(validated, crypto);
  return provider;
}

module.exports = { normalizeRelaySettings, publicRelaySettings, resolveRelayProviders, resolveModelDiscoveryProvider };
