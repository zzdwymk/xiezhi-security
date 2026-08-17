function selectEmbeddingTestConnection({
  mode,
  submitted,
  existing,
}) {
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

module.exports = { selectEmbeddingTestConnection };
