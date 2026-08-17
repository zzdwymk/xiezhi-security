const assert = require("node:assert/strict");
const {
  selectEmbeddingTestConnection,
} = require("../electron/ai-settings.cjs");

function select(mode, overrides = {}) {
  return selectEmbeddingTestConnection({
    mode,
    submitted: {
      baseUrl: "https://chat.example.com",
      embeddingBaseUrl: "https://embedding.example.com",
      apiKey: "",
      embeddingApiKey: "",
      ...overrides.submitted,
    },
    existing: {
      baseUrl: "https://chat.example.com",
      embeddingBaseUrl: "https://embedding.example.com",
      apiKey: "saved-chat-key",
      embeddingApiKey: "saved-embedding-key",
      ...overrides.existing,
    },
  });
}

const shared = select("shared", {
  submitted: {
    apiKey: "new-chat-key",
    embeddingApiKey: "wrong-embedding-key",
  },
});
assert.equal(shared.baseUrl, "https://chat.example.com");
assert.equal(shared.apiKey, "new-chat-key");
assert.equal(shared.requiresReplacementKey, false);

const custom = select("custom", {
  submitted: {
    apiKey: "wrong-chat-key",
    embeddingApiKey: "new-embedding-key",
  },
});
assert.equal(custom.baseUrl, "https://embedding.example.com");
assert.equal(custom.apiKey, "new-embedding-key");
assert.equal(custom.requiresReplacementKey, false);

assert.equal(select("shared").apiKey, "saved-chat-key");
assert.equal(select("custom").apiKey, "saved-embedding-key");

const changedShared = select("shared", {
  submitted: { baseUrl: "https://new-chat.example.com" },
});
assert.equal(changedShared.apiKey, "");
assert.equal(changedShared.addressChanged, true);
assert.equal(changedShared.requiresReplacementKey, true);

const changedSharedWithKey = select("shared", {
  submitted: {
    baseUrl: "https://new-chat.example.com",
    apiKey: "replacement-chat-key",
  },
});
assert.equal(changedSharedWithKey.apiKey, "replacement-chat-key");
assert.equal(changedSharedWithKey.requiresReplacementKey, false);

const changedCustom = select("custom", {
  submitted: { embeddingBaseUrl: "https://new-embedding.example.com" },
});
assert.equal(changedCustom.apiKey, "");
assert.equal(changedCustom.requiresReplacementKey, true);

const changedCustomWithKey = select("custom", {
  submitted: {
    embeddingBaseUrl: "https://new-embedding.example.com",
    embeddingApiKey: "replacement-embedding-key",
  },
});
assert.equal(changedCustomWithKey.apiKey, "replacement-embedding-key");
assert.equal(changedCustomWithKey.requiresReplacementKey, false);

const anonymousChangedCustom = select("custom", {
  submitted: { embeddingBaseUrl: "http://localhost:11434" },
  existing: { embeddingApiKey: "" },
});
assert.equal(anonymousChangedCustom.apiKey, "");
assert.equal(anonymousChangedCustom.addressChanged, true);
assert.equal(anonymousChangedCustom.requiresReplacementKey, false);

assert.equal(
  select("shared", {
    submitted: {
      embeddingBaseUrl: "https://unused-new-embedding.example.com",
    },
  }).requiresReplacementKey,
  false,
);
assert.equal(
  select("custom", {
    submitted: { baseUrl: "https://unused-new-chat.example.com" },
  }).requiresReplacementKey,
  false,
);

console.log("AI 向量连接设置测试通过。");
