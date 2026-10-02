function selectEmbeddingTestConnection({
  mode,
  relayEnabled = false,
  submitted,
  existing,
}) {
  if (relayEnabled && mode === "shared") {
    throw new Error("API 线路仅支持对话。向量检索请单独配置支持 Embedding 的服务，或使用 BM25 关键词检索。");
  }
  const shared = mode === "shared";
  const baseUrl = shared ? submitted.baseUrl : submitted.embeddingBaseUrl;
  const submittedKey = String(
    shared ? submitted.apiKey : submitted.embeddingApiKey,
  ).trim();
  const existingBaseUrl = shared
    ? existing.baseUrl
    : existing.embeddingBaseUrl;
  const existingKey = String(
    shared ? existing.apiKey : existing.embeddingApiKey,
  );
  const addressChanged = baseUrl !== existingBaseUrl;

  return {
    baseUrl,
    apiKey: submittedKey || (!addressChanged ? existingKey : ""),
    addressChanged,
    requiresReplacementKey:
      !submittedKey && Boolean(existingKey) && addressChanged,
  };
}

function runtimeModelEnvironment(settings) {
  const proxyMode = Boolean(settings.proxyMode);
  return {
    AI_RUNTIME_LLM_ENABLED: String(
      Boolean(settings.enabled && (settings.apiKey || proxyMode)),
    ),
    AI_RUNTIME_PROXY_MODE: String(proxyMode),
    AI_RUNTIME_API_MODE: settings.apiMode || "chat_completions",
    AI_RUNTIME_API_KEY: settings.apiKey || "",
  };
}

module.exports = { selectEmbeddingTestConnection, runtimeModelEnvironment };
