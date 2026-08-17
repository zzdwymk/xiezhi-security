const {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  nativeTheme,
  net: electronNet,
  safeStorage,
  session: electronSession,
  shell,
  systemPreferences,
} = require("electron");
const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const crypto = require("crypto");
const http = require("http");
const net = require("net");
const path = require("path");
const { fileURLToPath } = require("url");
const { Worker } = require("worker_threads");
const { readJsonFile, writeJsonFileAtomic } = require("./json-file.cjs");
const { createInvalidatableCache } = require("./invalidatable-cache.cjs");
const { evaluateInstalledRelease } = require("./dependency-version.cjs");
const { selectEmbeddingTestConnection } = require("./ai-settings.cjs");
const {
  UserFacingError,
  diagnosticError,
  publicErrorMessage,
} = require("./public-error.cjs");

let backendProcess;
let aiRuntimeProcess;
let aiRuntimeSpawn;
let startupWindow;
let mainWindow;
let backendPort;
let aiRuntimeConfig;
let aiRuntimeStartError;
let aiRuntimeTokenFile;
let aiRuntimeSigningSecretFile;
let shutdownToken;
let quitting = false;
let backendStartError;
let restartingBackend = false;
let aiSettingsOperation = Promise.resolve();
let captureBrowserWindow;
let captureBrowserSession;
let captureBrowserPartition;
let captureBrowserConfig;
let desktopCredentials;
let desktopLoginCredentialsIssued = false;

function readRegistryDword(key, name, fallback = 0) {
  if (process.platform !== "win32") return fallback;
  const result = spawnSync("reg.exe", ["query", key, "/v", name], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.status !== 0) return fallback;
  const match = String(result.stdout || "").match(
    new RegExp(`${name}\\s+REG_DWORD\\s+0x([0-9a-f]+)`, "i"),
  );
  return match ? Number.parseInt(match[1], 16) : fallback;
}

function argbDwordToHex(value, fallback) {
  if (!Number.isFinite(value)) return fallback;
  const unsigned = value >>> 0;
  const red = (unsigned >>> 16) & 0xff;
  const green = (unsigned >>> 8) & 0xff;
  const blue = unsigned & 0xff;
  return `#${[red, green, blue].map((channel) => channel.toString(16).padStart(2, "0")).join("")}`;
}

function relativeLuminance(hex) {
  const value = String(hex || "").replace(/^#/, "");
  const channels = [0, 2, 4].map(
    (offset) => Number.parseInt(value.slice(offset, offset + 2), 16) / 255,
  );
  const linear = channels.map((channel) =>
    channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
  );
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrastRatio(luminanceA, luminanceB) {
  const lighter = Math.max(luminanceA, luminanceB);
  const darker = Math.min(luminanceA, luminanceB);
  return (lighter + 0.05) / (darker + 0.05);
}

function contrastColor(hex) {
  const backgroundLuminance = relativeLuminance(hex);
  const darkForeground = "#111111";
  const lightForeground = "#ffffff";
  const darkContrast = contrastRatio(
    relativeLuminance(darkForeground),
    backgroundLuminance,
  );
  const lightContrast = contrastRatio(
    relativeLuminance(lightForeground),
    backgroundLuminance,
  );
  return darkContrast >= lightContrast ? darkForeground : lightForeground;
}

function titleBarOverlay(theme) {
  return {
    color: "rgba(0, 0, 0, 0)",
    symbolColor: theme.dark ? "#ffffff" : "#111111",
    height: 38,
  };
}

function windowBackgroundColor(theme) {
  return theme.transparencyEnabled && !theme.highContrast
    ? "#00000000"
    : theme.dark
      ? "#202020"
      : "#f3f3f3";
}

function sharedChromeSurface(theme) {
  if (
    !theme.transparencyEnabled ||
    theme.highContrast ||
    theme.windowMaterial === "none"
  ) {
    return theme.dark ? "#202020" : "#f3f3f3";
  }
  return theme.windowMaterial === "acrylic"
    ? "color-mix(in srgb, Canvas 32%, transparent)"
    : "color-mix(in srgb, Canvas 22%, transparent)";
}

function configuredWindowMaterial(settings = readDesktopSettings()) {
  if (["none", "mica", "acrylic"].includes(settings.windowMaterial))
    return settings.windowMaterial;
  return settings.micaEnabled === false ? "none" : "mica";
}

function computeSystemTheme() {
  const rawAccent = String(systemPreferences.getAccentColor() || "").replace(
    /^#/,
    "",
  );
  const accentColor = /^[0-9a-f]{6,8}$/i.test(rawAccent)
    ? `#${rawAccent.slice(0, 6)}`
    : "#0078d4";
  const dwmKey = "HKCU\\Software\\Microsoft\\Windows\\DWM";
  const personalizeKey =
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
  const desktopKey = "HKCU\\Control Panel\\Desktop";
  const appDark = nativeTheme.shouldUseDarkColors;
  const appsUseLightTheme =
    readRegistryDword(personalizeKey, "AppsUseLightTheme", appDark ? 0 : 1) !==
    0;
  const systemUsesLightTheme =
    readRegistryDword(
      personalizeKey,
      "SystemUsesLightTheme",
      appDark ? 0 : 1,
    ) !== 0;
  const systemTransparencyEnabled =
    readRegistryDword(personalizeKey, "EnableTransparency", 1) !== 0;
  const windowMaterial = configuredWindowMaterial();
  const transparencyEnabled =
    systemTransparencyEnabled && windowMaterial !== "none";
  const colorPrevalence = readRegistryDword(dwmKey, "ColorPrevalence", 0) !== 0;
  const autoColorization =
    readRegistryDword(desktopKey, "AutoColorization", 0) !== 0;
  const colorizationValue = readRegistryDword(
    dwmKey,
    "ColorizationColor",
    Number.NaN,
  );
  const captionColor = argbDwordToHex(colorizationValue, accentColor);
  const highContrast = nativeTheme.shouldUseHighContrastColors;
  // Keep the native DWM precedence: explicit caption accent, then Mica when
  // transparency is enabled, otherwise the opaque system theme fallback.
  const forcedCaptionAccent = false;
  const useAccentOnTitleBars =
    windowMaterial !== "none" &&
    colorPrevalence &&
    !systemUsesLightTheme &&
    !highContrast;
  const captionMode = useAccentOnTitleBars
    ? "accent"
    : transparencyEnabled && !highContrast
      ? "mica"
      : "solid";
  return {
    accentColor,
    captionColor,
    captionMode,
    useAccentOnTitleBars,
    forcedCaptionAccent,
    transparencyEnabled,
    windowMaterial,
    autoColorization,
    appsUseLightTheme,
    systemUsesLightTheme,
    dark: appDark,
    highContrast,
  };
}

const systemThemeCache = createInvalidatableCache(computeSystemTheme);

function currentSystemTheme() {
  return systemThemeCache.get();
}

function applyNativeBackdrop(window, theme = currentSystemTheme()) {
  if (!window || window.isDestroyed() || process.platform !== "win32") return;
  window.setBackgroundColor(windowBackgroundColor(theme));
  if (typeof window.setBackgroundMaterial === "function") {
    window.setBackgroundMaterial(
      theme.transparencyEnabled && !theme.highContrast
        ? theme.windowMaterial
        : "none",
    );
  }
}

function applySystemThemeToStaticWindow(window, theme = currentSystemTheme()) {
  if (!window || window.isDestroyed() || window.webContents.isDestroyed())
    return;
  const script = `(() => {
    const theme = ${JSON.stringify(theme)};
    const root = document.documentElement;
    root.style.setProperty('--system-accent', theme.accentColor);
    root.style.setProperty('--system-caption-color', theme.captionColor);
    root.style.setProperty('--system-theme-accent', theme.accentColor);
    root.style.setProperty('--system-accent-foreground', ${JSON.stringify(contrastColor(theme.accentColor))});
    root.style.setProperty('--shared-chrome-surface', ${JSON.stringify(sharedChromeSurface(theme))});
    root.style.colorScheme = theme.dark ? 'dark' : 'light';
    root.dataset.systemTheme = theme.dark ? 'dark' : 'light';
    root.dataset.captionMode = theme.captionMode;
    root.dataset.windowMaterial = theme.windowMaterial || 'none';
  })()`;
  void window.webContents.executeJavaScript(script).catch(() => {});
}

function broadcastSystemTheme() {
  const theme = currentSystemTheme();
  applyNativeBackdrop(mainWindow, theme);
  applyNativeBackdrop(startupWindow, theme);
  applyNativeBackdrop(captureBrowserWindow, theme);
  if (
    mainWindow &&
    !mainWindow.isDestroyed() &&
    !mainWindow.webContents.isDestroyed()
  ) {
    mainWindow.webContents.send("toolbox:system-theme-changed", theme);
  }
  applySystemThemeToStaticWindow(startupWindow, theme);
  applySystemThemeToStaticWindow(captureBrowserWindow, theme);
}

function handleSystemThemeChanged() {
  systemThemeCache.invalidate();
  broadcastSystemTheme();
}

function defaultToolsDirectory() {
  return app.isPackaged
    ? path.join(path.dirname(app.getPath("exe")), "tools")
    : path.resolve(__dirname, "..", "tools");
}

function settingsPath() {
  return path.join(app.getPath("userData"), "desktop-settings.json");
}

function loadDesktopSettings() {
  try {
    const parsed = JSON.parse(fs.readFileSync(settingsPath(), "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

const desktopSettingsCache = createInvalidatableCache(loadDesktopSettings);

function readDesktopSettings() {
  return desktopSettingsCache.get();
}

function writeDesktopSettings(settings) {
  const target = settingsPath();
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(settings, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
  if (fs.existsSync(target)) fs.unlinkSync(target);
  fs.renameSync(temporary, target);
  try {
    fs.chmodSync(target, 0o600);
  } catch {
    /* Windows protects userData through the current user's ACL. */
  }
  desktopSettingsCache.replace(settings);
  systemThemeCache.invalidate();
}

const DESKTOP_CREDENTIAL_SCHEMA_VERSION = 1;
const DESKTOP_MITM_CA_FILENAME = "traffic-mitm-ca.p12";

function assertSecureDesktopStorage() {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error("系统安全存储不可用，无法安全初始化桌面登录凭据");
  }
  if (
    process.platform === "linux" &&
    typeof safeStorage.getSelectedStorageBackend === "function" &&
    safeStorage.getSelectedStorageBackend() === "basic_text"
  ) {
    throw new Error(
      "系统密钥环不可用，Electron 只能使用明文存储后端，已拒绝初始化桌面登录凭据",
    );
  }
}

function generatedDesktopSecret(bytes = 48) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function validatedDesktopCredentials(value) {
  const credential = value && typeof value === "object" ? value : {};
  const validSecret = (secret, minimumLength) =>
    typeof secret === "string" &&
    secret.length >= minimumLength &&
    secret.length <= 256 &&
    /^[A-Za-z0-9_-]+$/.test(secret);
  // The admin password may be the auto-generated secret OR a password the user later sets in
  // Settings, so it is validated by length only. jwtSecret / mitmCaPassword remain strict random
  // secrets (never user-editable), so bundle-corruption is still detected by them.
  const validPassword = (secret) =>
    typeof secret === "string" && secret.length >= 8 && secret.length <= 128;
  if (
    credential.schemaVersion !== DESKTOP_CREDENTIAL_SCHEMA_VERSION ||
    credential.username !== "admin" ||
    !validPassword(credential.adminPassword) ||
    !validSecret(credential.jwtSecret, 43) ||
    !validSecret(credential.mitmCaPassword, 40)
  ) {
    throw new Error(
      "已保存的桌面安全凭据格式无效，请恢复 desktop-settings.json 的有效备份",
    );
  }
  return Object.freeze({
    schemaVersion: DESKTOP_CREDENTIAL_SCHEMA_VERSION,
    username: "admin",
    adminPassword: credential.adminPassword,
    jwtSecret: credential.jwtSecret,
    mitmCaPassword: credential.mitmCaPassword,
  });
}

function desktopMitmCaPath() {
  const dataDirectory = path.resolve(app.getPath("userData"), "data");
  const candidate = path.resolve(dataDirectory, DESKTOP_MITM_CA_FILENAME);
  if (
    path.dirname(candidate) !== dataDirectory ||
    path.basename(candidate) !== DESKTOP_MITM_CA_FILENAME
  ) {
    throw new Error("本地 HTTPS CA 路径未通过安全校验");
  }
  return candidate;
}

function desktopMitmMigrationPaths(migration) {
  const source = desktopMitmCaPath();
  const migrationId = String(migration?.id || "");
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      migrationId,
    )
  ) {
    throw new Error("本地 HTTPS CA 迁移记录无效");
  }
  const backupName = `${DESKTOP_MITM_CA_FILENAME}.desktop-credential-${migrationId}.bak`;
  const backup = path.resolve(path.dirname(source), backupName);
  if (
    path.dirname(backup) !== path.dirname(source) ||
    path.basename(backup) !== backupName
  ) {
    throw new Error("本地 HTTPS CA 备份路径未通过安全校验");
  }
  return { source, backup };
}

function ensureDesktopCredentials() {
  if (desktopCredentials) return desktopCredentials;
  assertSecureDesktopStorage();
  const settings = readDesktopSettings();
  const security =
    settings.desktopSecurity && typeof settings.desktopSecurity === "object"
      ? settings.desktopSecurity
      : {};
  if (security.encryptedCredentialBundle) {
    try {
      const decrypted = safeStorage.decryptString(
        Buffer.from(String(security.encryptedCredentialBundle), "base64"),
      );
      desktopCredentials = validatedDesktopCredentials(JSON.parse(decrypted));
      return desktopCredentials;
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error(
          "已保存的桌面安全凭据无法解析，请恢复 desktop-settings.json 的有效备份",
        );
      }
      if (
        error instanceof Error &&
        error.message.startsWith("已保存的桌面安全凭据")
      )
        throw error;
      throw new Error("已保存的桌面安全凭据无法由当前 Windows 用户解密");
    }
  }

  const credentials = validatedDesktopCredentials({
    schemaVersion: DESKTOP_CREDENTIAL_SCHEMA_VERSION,
    username: "admin",
    adminPassword: generatedDesktopSecret(48),
    jwtSecret: generatedDesktopSecret(64),
    mitmCaPassword: generatedDesktopSecret(48),
  });
  const legacyCaExists = fs.existsSync(desktopMitmCaPath());
  const encryptedCredentialBundle = safeStorage
    .encryptString(JSON.stringify(credentials))
    .toString("base64");
  const nextSecurity = {
    ...security,
    schemaVersion: DESKTOP_CREDENTIAL_SCHEMA_VERSION,
    encryptedCredentialBundle,
    ...(legacyCaExists
      ? { mitmCaMigration: { id: crypto.randomUUID(), state: "pending" } }
      : {}),
  };
  writeDesktopSettings({ ...settings, desktopSecurity: nextSecurity });
  desktopCredentials = credentials;
  return desktopCredentials;
}

function prepareDesktopMitmCaMigration() {
  const settings = readDesktopSettings();
  const migration = settings.desktopSecurity?.mitmCaMigration;
  if (!migration || migration.state !== "pending") return undefined;
  const paths = desktopMitmMigrationPaths(migration);
  fs.mkdirSync(path.dirname(paths.source), { recursive: true });
  if (!fs.existsSync(paths.backup) && fs.existsSync(paths.source)) {
    fs.renameSync(paths.source, paths.backup);
  }
  return { ...paths, id: migration.id };
}

function completeDesktopMitmCaMigration(migration) {
  if (!migration) return;
  const paths = desktopMitmMigrationPaths(migration);
  if (!fs.existsSync(paths.source))
    throw new Error("本地 HTTPS CA 安全轮换未生成新的密钥库");
  if (fs.existsSync(paths.backup)) fs.unlinkSync(paths.backup);
  const settings = readDesktopSettings();
  const security =
    settings.desktopSecurity && typeof settings.desktopSecurity === "object"
      ? { ...settings.desktopSecurity }
      : {};
  if (security.mitmCaMigration?.id === migration.id) {
    delete security.mitmCaMigration;
    writeDesktopSettings({ ...settings, desktopSecurity: security });
  }
}

function rollbackDesktopMitmCaMigration(migration) {
  if (!migration) return;
  const paths = desktopMitmMigrationPaths(migration);
  if (!fs.existsSync(paths.backup)) return;
  if (fs.existsSync(paths.source)) fs.unlinkSync(paths.source);
  fs.renameSync(paths.backup, paths.source);
}

const DEFAULT_AI_BASE_URL = "https://api.openai.com";
const DEFAULT_AI_MODEL = "gpt-4.1-mini";
const DEFAULT_AI_RETRIEVAL_BACKEND = "bm25";
const DEFAULT_AI_EMBEDDING_MODEL = "text-embedding-3-small";
const DEFAULT_AI_EMBEDDING_CONNECTION_MODE = "shared";

function normalizeAiBaseUrl(value) {
  const normalized = String(value || DEFAULT_AI_BASE_URL)
    .trim()
    .replace(/\/+$/, "");
  if (normalized.length > 2048)
    throw new UserFacingError("AI API 地址不能超过 2048 个字符");
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new UserFacingError("AI API 地址格式不正确");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new UserFacingError(
      "AI API 地址必须是有效的 HTTP 或 HTTPS 地址，且不能包含账号密码、查询参数或锚点",
    );
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (
    parsed.protocol === "http:" &&
    !["localhost", "127.0.0.1", "::1"].includes(hostname)
  ) {
    throw new UserFacingError(
      "远程 AI API 必须使用 HTTPS；HTTP 仅允许本机地址",
    );
  }
  let pathname = parsed.pathname.replace(/\/+$/, "");
  pathname = pathname
    .replace(/\/v1\/chat\/completions$/i, "")
    .replace(/\/v1$/i, "");
  parsed.pathname = pathname || "/";
  return parsed.toString().replace(/\/+$/, "");
}

function normalizeAiModel(value) {
  const model = String(value || DEFAULT_AI_MODEL).trim();
  if (!model || model.length > 120)
    throw new UserFacingError("模型名称不能为空且不能超过 120 个字符");
  return model;
}

function normalizeAiRetrievalBackend(value) {
  const backend = String(value || DEFAULT_AI_RETRIEVAL_BACKEND)
    .trim()
    .toLowerCase();
  if (!["bm25", "real_embedding"].includes(backend)) {
    throw new UserFacingError("检索后端只能是 BM25 或真实向量嵌入");
  }
  return backend;
}

function normalizeAiEmbeddingModel(value) {
  const model = String(value || DEFAULT_AI_EMBEDDING_MODEL).trim();
  if (!model || model.length > 120) {
    throw new UserFacingError("Embedding 模型名称不能为空且不能超过 120 个字符");
  }
  return model;
}

function normalizeAiEmbeddingBaseUrl(value, fallback) {
  return normalizeAiBaseUrl(value || fallback || DEFAULT_AI_BASE_URL);
}

function normalizeAiEmbeddingConnectionMode(value) {
  const mode = String(value || DEFAULT_AI_EMBEDDING_CONNECTION_MODE)
    .trim()
    .toLowerCase();
  if (!["shared", "custom"].includes(mode)) {
    throw new UserFacingError("向量模型连接方式只能是复用对话连接或单独配置");
  }
  return mode;
}

function decryptStoredApiKey(settings = readDesktopSettings()) {
  const encrypted = settings.ai?.encryptedApiKey;
  if (!encrypted) return "";
  if (!safeStorage.isEncryptionAvailable())
    throw new UserFacingError("当前系统无法解密已保存的 API Key");
  try {
    return safeStorage.decryptString(Buffer.from(encrypted, "base64"));
  } catch {
    throw new UserFacingError("已保存的 API Key 无法解密，请清除后重新填写");
  }
}

function resolvedAiSettings(settings = readDesktopSettings()) {
  const stored =
    settings.ai && typeof settings.ai === "object" ? settings.ai : undefined;
  const apiKey = stored?.apiKeyCleared
    ? ""
    : stored?.encryptedApiKey
      ? decryptStoredApiKey(settings)
      : String(process.env.AI_API_KEY || "");
  const environmentEnabled =
    String(process.env.AI_ENABLED || "").toLowerCase() === "true";
  const proxyMode = stored
    ? Boolean(stored.proxyMode)
    : environmentEnabled && !apiKey;
  const environmentEmbeddingConfigured = Boolean(
    process.env.AI_RUNTIME_EMBEDDING_BASE_URL ||
      process.env.AI_RUNTIME_EMBEDDING_API_KEY,
  );
  const embeddingConnectionMode = normalizeAiEmbeddingConnectionMode(
    stored?.embeddingConnectionMode ||
      (environmentEmbeddingConfigured ? "custom" : "shared"),
  );
  const customEmbeddingApiKey = stored?.embeddingApiKeyCleared
    ? ""
    : stored?.encryptedEmbeddingApiKey
      ? decryptStoredEmbeddingApiKey(settings)
      : String(process.env.AI_RUNTIME_EMBEDDING_API_KEY || "");
  const baseUrl = normalizeAiBaseUrl(
    stored?.baseUrl || process.env.AI_BASE_URL || DEFAULT_AI_BASE_URL,
  );
  const embeddingBaseUrl = normalizeAiEmbeddingBaseUrl(
    stored?.embeddingBaseUrl || process.env.AI_RUNTIME_EMBEDDING_BASE_URL,
    baseUrl,
  );
  return {
    baseUrl,
    model: normalizeAiModel(
      stored?.model || process.env.AI_MODEL || DEFAULT_AI_MODEL,
    ),
    retrievalBackend: normalizeAiRetrievalBackend(
      stored?.retrievalBackend ||
        process.env.AI_RUNTIME_RETRIEVAL_BACKEND ||
        DEFAULT_AI_RETRIEVAL_BACKEND,
    ),
    embeddingModel: normalizeAiEmbeddingModel(
      stored?.embeddingModel ||
        process.env.AI_RUNTIME_EMBEDDING_MODEL ||
        DEFAULT_AI_EMBEDDING_MODEL,
    ),
    embeddingConnectionMode,
    embeddingBaseUrl,
    customEmbeddingApiKey,
    effectiveEmbeddingBaseUrl:
      embeddingConnectionMode === "shared" ? baseUrl : embeddingBaseUrl,
    effectiveEmbeddingApiKey:
      embeddingConnectionMode === "shared" ? apiKey : customEmbeddingApiKey,
    apiKey,
    proxyMode,
    enabled: Boolean(apiKey || proxyMode || environmentEnabled),
    apiMode: proxyMode ? "responses" : "chat_completions",
  };
}

function publicAiSettings(settings = readDesktopSettings()) {
  const resolved = resolvedAiSettings(settings);
  return {
    baseUrl: resolved.baseUrl,
    model: resolved.model,
    retrievalBackend: resolved.retrievalBackend,
    embeddingModel: resolved.embeddingModel,
    embeddingConnectionMode: resolved.embeddingConnectionMode,
    embeddingBaseUrl: resolved.embeddingBaseUrl,
    hasEmbeddingApiKey: Boolean(resolved.customEmbeddingApiKey),
    embeddingKeyHint: resolved.customEmbeddingApiKey
      ? `末尾 ${resolved.customEmbeddingApiKey.slice(-4)}`
      : "",
    hasApiKey: Boolean(resolved.apiKey),
    keyHint: resolved.apiKey ? `末尾 ${resolved.apiKey.slice(-4)}` : "",
    proxyMode: resolved.proxyMode,
    apiMode: resolved.apiMode,
    provider: resolved.enabled ? "openai-compatible" : "local-rule-fallback",
    encryptionAvailable: safeStorage.isEncryptionAvailable(),
  };
}

function updatedAiSettings(
  previousSettings,
  payload,
  { clearApiKey = false, clearEmbeddingApiKey = false } = {},
) {
  const existing =
    previousSettings.ai && typeof previousSettings.ai === "object"
      ? previousSettings.ai
      : {};
  const previousResolved = resolvedAiSettings(previousSettings);
  const baseUrl = normalizeAiBaseUrl(payload?.baseUrl);
  const apiKey = String(payload?.apiKey || "").trim();
  const embeddingApiKey = String(payload?.embeddingApiKey || "").trim();
  const proxyMode = Boolean(payload?.proxyMode);
  const embeddingConnectionMode = normalizeAiEmbeddingConnectionMode(
    payload?.embeddingConnectionMode,
  );
  const embeddingBaseUrl = normalizeAiEmbeddingBaseUrl(
    payload?.embeddingBaseUrl,
    baseUrl,
  );
  if (
    !clearApiKey &&
    !proxyMode &&
    !apiKey &&
    previousResolved.apiKey &&
    baseUrl !== previousResolved.baseUrl
  ) {
    throw new UserFacingError(
      "API 地址已变化，请重新填写与新服务对应的 API Key",
    );
  }
  if (
    !clearEmbeddingApiKey &&
    embeddingConnectionMode === "custom" &&
    !embeddingApiKey &&
    previousResolved.customEmbeddingApiKey &&
    embeddingBaseUrl !== previousResolved.embeddingBaseUrl
  ) {
    throw new UserFacingError(
      "向量 API 地址已变化，请重新填写与新服务对应的向量 API Key",
    );
  }
  const nextAi = {
    ...existing,
    baseUrl,
    model: normalizeAiModel(payload?.model),
    retrievalBackend: normalizeAiRetrievalBackend(payload?.retrievalBackend),
    embeddingModel: normalizeAiEmbeddingModel(payload?.embeddingModel),
    embeddingConnectionMode,
    embeddingBaseUrl,
    proxyMode,
  };
  if (clearApiKey) {
    delete nextAi.encryptedApiKey;
    nextAi.apiKeyCleared = true;
  } else if (apiKey) {
    if (!safeStorage.isEncryptionAvailable()) {
      throw new UserFacingError("系统安全存储不可用，无法安全保存 API Key");
    }
    nextAi.encryptedApiKey = safeStorage
      .encryptString(apiKey)
      .toString("base64");
    delete nextAi.apiKeyCleared;
  } else if (
    proxyMode &&
    previousResolved.apiKey &&
    baseUrl !== previousResolved.baseUrl
  ) {
    delete nextAi.encryptedApiKey;
    nextAi.apiKeyCleared = true;
  }
  if (clearEmbeddingApiKey) {
    delete nextAi.encryptedEmbeddingApiKey;
    nextAi.embeddingApiKeyCleared = true;
  } else if (embeddingApiKey) {
    if (!safeStorage.isEncryptionAvailable()) {
      throw new UserFacingError("系统安全存储不可用，无法安全保存向量 API Key");
    }
    nextAi.encryptedEmbeddingApiKey = safeStorage
      .encryptString(embeddingApiKey)
      .toString("base64");
    delete nextAi.embeddingApiKeyCleared;
  }
  return { ...previousSettings, ai: nextAi };
}

function normalizeIcpApiUrl(value) {
  const raw = String(value || "").trim();
  if (!raw || raw.length > 2048)
    throw new UserFacingError("ICP API 地址不能为空且不能超过 2048 个字符");
  let parsed;
  try {
    parsed = new URL(raw.replaceAll("{domain}", "example.com"));
  } catch {
    throw new UserFacingError("ICP API 地址格式不正确");
  }
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    throw new UserFacingError(
      "ICP API 必须是有效的 HTTPS 地址，且不能包含账号密码或锚点",
    );
  }
  return raw;
}

function decryptStoredIcpApiUrl(settings = readDesktopSettings()) {
  const encrypted = settings.recon?.encryptedIcpApiUrl;
  if (!encrypted) return "";
  if (!safeStorage.isEncryptionAvailable()) {
    throw new UserFacingError("当前系统无法解密已保存的 ICP API 地址");
  }
  try {
    return safeStorage.decryptString(Buffer.from(encrypted, "base64"));
  } catch {
    throw new UserFacingError(
      "已保存的 ICP API 地址无法解密，请清除后重新填写",
    );
  }
}

function resolvedIcpSettings(settings = readDesktopSettings()) {
  const stored =
    settings.recon && typeof settings.recon === "object"
      ? settings.recon
      : undefined;
  const configured = stored?.icpApiUrlCleared
    ? ""
    : stored?.encryptedIcpApiUrl
      ? decryptStoredIcpApiUrl(settings)
      : String(process.env.ICP_API_URL || "").trim();
  return {
    apiUrl: configured ? normalizeIcpApiUrl(configured) : "",
    source: stored?.encryptedIcpApiUrl
      ? "desktop"
      : configured
        ? "environment"
        : "none",
  };
}

function publicIcpSettings(settings = readDesktopSettings()) {
  const resolved = resolvedIcpSettings(settings);
  let endpointHint = "";
  if (resolved.apiUrl) {
    const parsed = new URL(
      resolved.apiUrl.replaceAll("{domain}", "example.com"),
    );
    endpointHint = `${parsed.hostname}${parsed.pathname === "/" ? "" : parsed.pathname}${parsed.search ? "?••••" : ""}`;
  }
  return {
    configured: Boolean(resolved.apiUrl),
    endpointHint,
    source: resolved.source,
    encryptionAvailable: safeStorage.isEncryptionAvailable(),
  };
}

function updatedIcpSettings(previousSettings, payload, clear = false) {
  const existing =
    previousSettings.recon && typeof previousSettings.recon === "object"
      ? previousSettings.recon
      : {};
  const nextRecon = { ...existing };
  if (clear) {
    delete nextRecon.encryptedIcpApiUrl;
    nextRecon.icpApiUrlCleared = true;
  } else {
    const apiUrl = normalizeIcpApiUrl(payload?.apiUrl);
    if (!safeStorage.isEncryptionAvailable()) {
      throw new UserFacingError(
        "系统安全存储不可用，无法安全保存 ICP API 地址",
      );
    }
    nextRecon.encryptedIcpApiUrl = safeStorage
      .encryptString(apiUrl)
      .toString("base64");
    delete nextRecon.icpApiUrlCleared;
  }
  return { ...previousSettings, recon: nextRecon };
}

function serializeAiSettingsOperation(operation) {
  const next = aiSettingsOperation.catch(() => {}).then(operation);
  aiSettingsOperation = next;
  return next;
}

async function testAiConnection(payload) {
  const existing = resolvedAiSettings();
  const baseUrl = normalizeAiBaseUrl(payload?.baseUrl);
  const model = normalizeAiModel(payload?.model);
  const submittedApiKey = String(payload?.apiKey || "").trim();
  const proxyMode = Boolean(payload?.proxyMode);
  if (
    !proxyMode &&
    !submittedApiKey &&
    existing.apiKey &&
    baseUrl !== existing.baseUrl
  ) {
    throw new UserFacingError(
      "API 地址已变化，请填写新服务对应的 API Key 后再测试",
    );
  }
  const apiKey =
    submittedApiKey || (baseUrl === existing.baseUrl ? existing.apiKey : "");
  if (!apiKey && !proxyMode)
    throw new UserFacingError("请先填写 API Key，或启用 CCS 本地代理模式");
  const controller = new AbortController();
  const timeoutMs = proxyMode ? 90000 : 20000;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = { "Content-Type": "application/json" };
    let endpoint = `${baseUrl}/v1/chat/completions`;
    let body;
    if (proxyMode) {
      headers.Authorization = `Bearer ${apiKey || "ccs-proxy"}`;
      headers["OpenAI-Beta"] = "responses=experimental";
      headers.originator = "codex_cli_rs";
      headers["User-Agent"] = "codex_cli_rs/secbox";
      endpoint = `${baseUrl}/v1/responses`;
      body = {
        model,
        instructions: "You are a concise assistant.",
        input: [
          {
            type: "message",
            role: "user",
            content: [{ type: "input_text", text: "Reply with OK only." }],
          },
        ],
        tools: [],
        tool_choice: "auto",
        parallel_tool_calls: true,
        reasoning: { effort: "medium", summary: "auto" },
        text: { verbosity: "low" },
        store: false,
        stream: true,
        include: ["reasoning.encrypted_content"],
        prompt_cache_key: `secbox-test-${crypto.randomUUID()}`,
      };
    } else {
      if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
      body = { model, messages: [{ role: "user", content: "请只回复 OK" }] };
    }
    const response = await electronNet.fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new UserFacingError(
        `AI API 返回错误状态（HTTP ${response.status}）`,
      );
    }
    let content;
    if (proxyMode) {
      const streamText = await response.text();
      content = streamText
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data: "))
        .map((line) => {
          try {
            return JSON.parse(line.slice(6));
          } catch {
            return undefined;
          }
        })
        .filter((event) => event?.type === "response.output_text.delta")
        .map((event) => event.delta || "")
        .join("");
    } else {
      const responseBody = await response.json();
      content = responseBody?.choices?.[0]?.message?.content;
    }
    if (typeof content !== "string" || !content.trim()) {
      throw new UserFacingError("AI API 已响应，但没有返回对话内容");
    }
    return { ok: true, model, message: content.trim().slice(0, 120) };
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new UserFacingError(`AI API 连接超时（${timeoutMs / 1000} 秒）`);
    }
    if (error instanceof UserFacingError) throw error;
    writeDesktopStartupDiagnostic("ai-connection-test", error);
    throw new UserFacingError("无法连接 AI API，请检查网络和服务配置");
  } finally {
    clearTimeout(timeout);
  }
}

function resolveToolsDirectory() {
  const configured = readDesktopSettings().toolsDirectory;
  return typeof configured === "string" && path.isAbsolute(configured)
    ? path.normalize(configured)
    : defaultToolsDirectory();
}

function resolvePortableNmapPath(toolsDir) {
  const executableName = process.platform === "win32" ? "nmap.exe" : "nmap";
  const candidate = path.join(toolsDir, "nmap", executableName);
  try {
    return fs.statSync(candidate).isFile() ? candidate : undefined;
  } catch {
    return undefined;
  }
}

function ensureWritableDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true });
  const probe = path.join(
    directory,
    `.security-toolbox-write-test-${crypto.randomUUID()}`,
  );
  fs.writeFileSync(probe, "ok", { flag: "wx" });
  fs.unlinkSync(probe);
}

const INSTALLABLE_PACKAGES = Object.freeze({
  nuclei: Object.freeze({
    id: "nuclei",
    optional: true,
    repository: "projectdiscovery/nuclei",
    executable: "nuclei.exe",
    assetName: (version) => `nuclei_${version}_windows_amd64.zip`,
    checksumName: (version) => `nuclei_${version}_checksums.txt`,
  }),
  httpx: Object.freeze({
    id: "httpx",
    optional: true,
    repository: "projectdiscovery/httpx",
    executable: "httpx.exe",
    assetName: (version) => `httpx_${version}_windows_amd64.zip`,
    checksumName: (version) => `httpx_${version}_checksums.txt`,
  }),
  xray: Object.freeze({
    id: "xray",
    optional: true,
    repository: "chaitin/xray",
    executable: "xray_windows_amd64.exe",
    assetName: () => "xray_windows_amd64.exe.zip",
    checksumName: () => "sha256.txt",
    // chaitin/xray's GitHub "latest" release currently points to xpoc,
    // so select the newest stable semantic-version release that actually
    // contains the exact Xray Windows x64 asset.
    releaseMode: "latest-semver-match",
  }),
  afrog: Object.freeze({
    id: "afrog",
    optional: true,
    repository: "zan8in/afrog",
    executable: "afrog.exe",
    assetName: (version) => `afrog_${version}_windows_amd64.zip`,
    checksumName: (version) => `afrog_${version}_checksums.txt`,
  }),
});

class GithubRateLimitError extends UserFacingError {}

// GitHub's REST API rejects unauthenticated calls once the per-IP budget (60/hour) is spent —
// on a shared campus/office NAT that happens fast and surfaces as HTTP 403. A personal access
// token raises the budget to 5000/hour and is the real fix; we also always send the headers
// GitHub documents as required.
function githubTokenSettingsPath() {
  return path.join(app.getPath("userData"), "github-token.json");
}

function isPlausibleGithubToken(token) {
  return /^[A-Za-z0-9_.-]{20,255}$/.test(String(token || "").trim());
}

function resolveGithubToken() {
  const envToken = String(
    process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "",
  ).trim();
  if (isPlausibleGithubToken(envToken))
    return { token: envToken, source: "env" };
  try {
    const saved = readJsonFile(githubTokenSettingsPath());
    if (!saved || !saved.encryptedToken || !safeStorage.isEncryptionAvailable())
      return { token: "", source: "none" };
    const token = safeStorage
      .decryptString(Buffer.from(String(saved.encryptedToken), "base64"))
      .trim();
    if (isPlausibleGithubToken(token)) return { token, source: "settings" };
  } catch {}
  return { token: "", source: "none" };
}

function publicGithubTokenSettings() {
  const resolved = resolveGithubToken();
  return {
    configured: Boolean(resolved.token),
    source: resolved.source,
    encryptionAvailable: safeStorage.isEncryptionAvailable(),
    hint: resolved.token
      ? resolved.token.slice(0, 4) +
        "…" +
        resolved.token.slice(-4) +
        (resolved.source === "env" ? "（环境变量）" : "（安全存储）")
      : "",
  };
}

function saveGithubTokenSettings(payload = {}) {
  const clear = Boolean(payload.clear);
  const token = String(payload.token || "").trim();
  const target = githubTokenSettingsPath();
  if (clear || !token) {
    if (fs.existsSync(target)) fs.rmSync(target, { force: true });
    return publicGithubTokenSettings();
  }
  if (!isPlausibleGithubToken(token))
    throw new UserFacingError("GitHub Token 格式无效");
  if (!safeStorage.isEncryptionAvailable()) {
    throw new UserFacingError("系统安全存储不可用，无法保存 GitHub Token");
  }
  writeJsonFileAtomic(target, {
    encryptedToken: safeStorage.encryptString(token).toString("base64"),
    updatedAt: new Date().toISOString(),
  });
  return publicGithubTokenSettings();
}

function githubApiHeaders() {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "Xiezhi-Security/0.2",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  const resolved = resolveGithubToken();
  if (resolved.token) headers.Authorization = "Bearer " + resolved.token;
  return headers;
}

function githubApiError(response) {
  if (response.status === 403 || response.status === 429) {
    const remaining = response.headers.get("x-ratelimit-remaining");
    const resetEpoch = Number(response.headers.get("x-ratelimit-reset") || 0);
    if (response.status === 429 || remaining === "0") {
      const when =
        resetEpoch > 0
          ? `，请于 ${new Date(resetEpoch * 1000).toLocaleTimeString()} 后重试`
          : "";
      return new GithubRateLimitError(
        `GitHub API 访问频率超限（未登录时每小时仅 60 次，校园/公司共享出口 IP 很快用尽）${when}。` +
          "请到「系统设置 → GitHub 访问令牌」配置 Personal Access Token，或设置环境变量 GITHUB_TOKEN/GH_TOKEN 后重试。应用会在 API 限流时自动尝试备用下载通道。",
      );
    }
    return new GithubRateLimitError(
      "GitHub API 拒绝了请求（HTTP 403），可能受访问频率或网络策略限制。",
    );
  }
  return new UserFacingError(`查询最新版本失败：HTTP ${response.status}`);
}

const activeInstalls = new Map();
const latestPackageCache = new Map();
const DEPENDENCY_CONNECT_TIMEOUT_MS = 30000;
const DEPENDENCY_IDLE_TIMEOUT_MS = 45000;

async function openDependencyResource(
  url,
  options = {},
  timeoutMs = DEPENDENCY_CONNECT_TIMEOUT_MS,
) {
  const externalSignal = options.signal;
  const controller = new AbortController();
  let timeoutMessage = "";
  let timeout;
  const relayAbort = () => controller.abort();
  if (externalSignal?.aborted) controller.abort();
  else externalSignal?.addEventListener("abort", relayAbort, { once: true });
  const armTimeout = (message, delay = timeoutMs) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => {
      timeoutMessage = message;
      controller.abort();
    }, delay);
  };
  const dispose = () => {
    clearTimeout(timeout);
    externalSignal?.removeEventListener("abort", relayAbort);
  };
  armTimeout(`连接下载源超时（${Math.round(timeoutMs / 1000)} 秒）`);
  try {
    const response = await electronNet.fetch(url, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(timeout);
    return {
      response,
      armTimeout,
      dispose,
      timeoutError: () => timeoutMessage,
    };
  } catch (error) {
    dispose();
    if (timeoutMessage) throw new UserFacingError(timeoutMessage);
    throw error;
  }
}

async function fetchDependencyResource(
  url,
  options = {},
  timeoutMs = DEPENDENCY_CONNECT_TIMEOUT_MS,
) {
  const request = await openDependencyResource(url, options, timeoutMs);
  request.dispose();
  return request.response;
}

async function fetchDependencyText(
  url,
  { maxBytes, allowedHosts, headers = {} },
) {
  const request = await openDependencyResource(url, { headers });
  const response = request.response;
  try {
    if (!response.ok || !response.body) {
      throw new UserFacingError(`下载文本资源失败：HTTP ${response.status}`);
    }
    allowedResponseHost(response, url, allowedHosts);
    const declaredLength = Number(response.headers.get("content-length") || 0);
    if (declaredLength > maxBytes)
      throw new UserFacingError("文本资源超过安全大小限制");
    const chunks = [];
    let totalBytes = 0;
    const reader = response.body.getReader();
    while (true) {
      request.armTimeout(
        `下载文本资源连续 ${Math.round(DEPENDENCY_IDLE_TIMEOUT_MS / 1000)} 秒没有收到数据`,
        DEPENDENCY_IDLE_TIMEOUT_MS,
      );
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new UserFacingError("文本资源超过安全大小限制");
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks, totalBytes).toString("utf8");
  } catch (error) {
    if (request.timeoutError())
      throw new UserFacingError(request.timeoutError());
    throw error;
  } finally {
    request.dispose();
  }
}

function runDependencyWorker(task, payload, onProgress = () => {}) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, "dependency-worker.cjs"), {
      workerData: { task, payload },
    });
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    worker.on("message", (message) => {
      if (!message || typeof message !== "object") return;
      if (message.type === "progress") onProgress(message);
      else if (message.type === "result") finish(resolve, message.result);
      else if (message.type === "error") {
        if (message.diagnostic) {
          writeDesktopStartupDiagnostic(
            "dependency-worker",
            message.diagnostic,
            { task },
          );
        }
        finish(
          reject,
          new UserFacingError(
            String(message.message || "后台安装任务失败，请稍后重试"),
          ),
        );
      }
    });
    worker.on("error", (error) => {
      writeDesktopStartupDiagnostic("dependency-worker", error, { task });
      finish(reject, new UserFacingError("后台安装任务失败，请稍后重试"));
    });
    worker.on("exit", (code) => {
      if (settled) return;
      writeDesktopStartupDiagnostic(
        "dependency-worker-exit",
        `后台任务退出代码：${code}`,
        { task },
      );
      finish(reject, new UserFacingError("后台安装任务未正常完成，请稍后重试"));
    });
  });
}

function dependencyInterrupted(action) {
  const error = new UserFacingError(
    action === "cancel" ? "依赖下载已取消" : "依赖下载已暂停",
  );
  error.code =
    action === "cancel"
      ? "DEPENDENCY_DOWNLOAD_CANCELED"
      : "DEPENDENCY_DOWNLOAD_PAUSED";
  return error;
}

function throwIfDependencyInterrupted(session) {
  if (session.intent === "cancel" || session.intent === "pause")
    throw dependencyInterrupted(session.intent);
}

function hasRunningInstalls() {
  return [...activeInstalls.values()].some(
    (session) => session.state !== "paused",
  );
}

function assertInside(parent, child) {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new UserFacingError("安装路径超出工具目录");
  }
}

function assertSafeInstallDirectory(directory) {
  if (!fs.existsSync(directory)) {
    fs.mkdirSync(directory, { recursive: true });
    return;
  }
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw new UserFacingError("工具安装目录类型异常");
}

function assertReplaceableInstallFile(filePath, label) {
  if (!fs.existsSync(filePath)) return false;
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new UserFacingError(`${label}文件类型异常，已拒绝覆盖`);
  }
  return true;
}

function promotePortableInstall({
  toolsDir,
  stagingDir,
  targetDir,
  stagedExecutable,
  targetExecutable,
  sourceMetadata,
}) {
  assertInside(toolsDir, stagingDir);
  assertInside(toolsDir, targetDir);
  assertSafeInstallDirectory(targetDir);
  const stagedMetadata = path.join(stagingDir, ".toolbox-source.json");
  const targetMetadata = path.join(targetDir, ".toolbox-source.json");
  const transactionId = crypto.randomUUID();
  const executableBackup = path.join(
    targetDir,
    `.toolbox-backup-${transactionId}-${path.basename(targetExecutable)}`,
  );
  const metadataBackup = path.join(
    targetDir,
    `.toolbox-backup-${transactionId}-source.json`,
  );
  [stagedMetadata, targetMetadata, executableBackup, metadataBackup].forEach(
    (candidate) => assertInside(toolsDir, candidate),
  );
  assertReplaceableInstallFile(stagedExecutable, "暂存工具");
  fs.writeFileSync(stagedMetadata, JSON.stringify(sourceMetadata, null, 2), {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });

  const hadExecutable = assertReplaceableInstallFile(
    targetExecutable,
    "现有工具",
  );
  const hadMetadata = assertReplaceableInstallFile(
    targetMetadata,
    "现有来源记录",
  );
  let executablePromoted = false;
  let metadataPromoted = false;
  try {
    if (hadExecutable) fs.renameSync(targetExecutable, executableBackup);
    if (hadMetadata) fs.renameSync(targetMetadata, metadataBackup);
    fs.renameSync(stagedExecutable, targetExecutable);
    executablePromoted = true;
    fs.renameSync(stagedMetadata, targetMetadata);
    metadataPromoted = true;
  } catch (error) {
    if (metadataPromoted && fs.existsSync(targetMetadata))
      fs.unlinkSync(targetMetadata);
    if (executablePromoted && fs.existsSync(targetExecutable))
      fs.unlinkSync(targetExecutable);
    if (
      hadMetadata &&
      fs.existsSync(metadataBackup) &&
      !fs.existsSync(targetMetadata)
    ) {
      fs.renameSync(metadataBackup, targetMetadata);
    }
    if (
      hadExecutable &&
      fs.existsSync(executableBackup) &&
      !fs.existsSync(targetExecutable)
    ) {
      fs.renameSync(executableBackup, targetExecutable);
    }
    throw error;
  }
  // The new executable and its source record are now committed. A locked
  // stale backup is harmless and safer than rolling back a valid install.
  if (hadExecutable) {
    try {
      fs.unlinkSync(executableBackup);
    } catch {
      /* cleaned on a later maintenance pass */
    }
  }
  if (hadMetadata) {
    try {
      fs.unlinkSync(metadataBackup);
    } catch {
      /* cleaned on a later maintenance pass */
    }
  }
}

function removeDownloadState(filePath, metadataPath) {
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  if (fs.existsSync(metadataPath)) fs.unlinkSync(metadataPath);
}

function readDownloadMetadata(metadataPath) {
  if (!fs.existsSync(metadataPath)) return undefined;
  const stat = fs.lstatSync(metadataPath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024)
    return undefined;
  try {
    return JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  } catch {
    return undefined;
  }
}

function writeDownloadMetadata(metadataPath, value) {
  const temporaryPath = `${metadataPath}.tmp`;
  fs.writeFileSync(temporaryPath, JSON.stringify(value), { flag: "w" });
  if (fs.existsSync(metadataPath)) fs.unlinkSync(metadataPath);
  fs.renameSync(temporaryPath, metadataPath);
}

function partialFileSize(filePath) {
  if (!fs.existsSync(filePath)) return 0;
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink())
    throw new UserFacingError("未完成下载文件类型异常");
  return stat.size;
}

function parseContentRange(value) {
  const match = String(value || "").match(/^bytes\s+(\d+)-(\d+)\/(\d+)$/i);
  if (!match) return undefined;
  const start = Number(match[1]);
  const end = Number(match[2]);
  const total = Number(match[3]);
  if (
    ![start, end, total].every(Number.isSafeInteger) ||
    start < 0 ||
    end < start ||
    total <= end
  )
    return undefined;
  return { start, end, total };
}

async function downloadResumableFile({
  url,
  filePath,
  metadataPath,
  expectedSha256,
  expectedSize = 0,
  maxBytes,
  allowedHosts,
  signal,
  onProgress = () => {},
}) {
  const identity = { url, expectedSha256, expectedSize };
  let metadata = readDownloadMetadata(metadataPath);
  if (
    metadata &&
    (metadata.url !== url ||
      metadata.expectedSha256 !== expectedSha256 ||
      Number(metadata.expectedSize || 0) !== Number(expectedSize || 0))
  ) {
    removeDownloadState(filePath, metadataPath);
    metadata = undefined;
  }

  let offset = partialFileSize(filePath);
  let effectiveExpectedSize = Number(expectedSize || metadata?.totalBytes || 0);
  if (offset > 0 && !metadata) {
    removeDownloadState(filePath, metadataPath);
    offset = 0;
  }
  if (
    offset > maxBytes ||
    (effectiveExpectedSize > 0 && offset > effectiveExpectedSize)
  ) {
    removeDownloadState(filePath, metadataPath);
    offset = 0;
  }
  if (effectiveExpectedSize > maxBytes)
    throw new UserFacingError("下载文件超过安全大小限制");
  if (
    offset > 0 &&
    effectiveExpectedSize > 0 &&
    offset === effectiveExpectedSize
  ) {
    onProgress({
      receivedBytes: offset,
      totalBytes: effectiveExpectedSize,
      resumedBytes: offset,
      complete: true,
    });
    return {
      size: offset,
      totalBytes: effectiveExpectedSize,
      resumedBytes: offset,
      rangeAccepted: true,
    };
  }

  const requestedOffset = offset;
  const headers = { "Accept-Encoding": "identity" };
  if (offset > 0) {
    headers.Range = `bytes=${offset}-`;
    const validator =
      typeof metadata?.etag === "string" && !metadata.etag.startsWith("W/")
        ? metadata.etag
        : metadata?.lastModified;
    if (validator) headers["If-Range"] = validator;
  }
  const request = await openDependencyResource(url, { headers, signal });
  const response = request.response;
  try {
    allowedResponseHost(response, url, allowedHosts);

    const contentEncoding = String(
      response.headers.get("content-encoding") || "identity",
    ).toLowerCase();
    if (contentEncoding !== "identity") {
      removeDownloadState(filePath, metadataPath);
      throw new UserFacingError("下载源返回了不适用于断点续传的内容编码");
    }

    let append = false;
    let rangeAccepted = false;
    let totalBytes = effectiveExpectedSize;
    if (offset > 0 && response.status === 206) {
      const range = parseContentRange(response.headers.get("content-range"));
      const declaredLength = Number(
        response.headers.get("content-length") || 0,
      );
      if (
        !range ||
        range.start !== offset ||
        (effectiveExpectedSize > 0 && range.total !== effectiveExpectedSize) ||
        (declaredLength > 0 && declaredLength !== range.end - range.start + 1)
      ) {
        removeDownloadState(filePath, metadataPath);
        throw new UserFacingError(
          "下载源返回的断点范围不一致，已丢弃不可信的未完成文件",
        );
      }
      append = true;
      rangeAccepted = true;
      totalBytes = range.total;
    } else if (response.status === 200) {
      const declaredLength = Number(
        response.headers.get("content-length") || 0,
      );
      if (
        effectiveExpectedSize > 0 &&
        declaredLength > 0 &&
        declaredLength !== effectiveExpectedSize
      ) {
        removeDownloadState(filePath, metadataPath);
        throw new UserFacingError("下载文件大小与官方发布记录不一致");
      }
      if (offset > 0) {
        onProgress({
          restarted: true,
          receivedBytes: 0,
          totalBytes: effectiveExpectedSize || declaredLength,
        });
      }
      offset = 0;
      totalBytes = effectiveExpectedSize || declaredLength;
    } else if (offset > 0 && response.status === 416) {
      const match = String(response.headers.get("content-range") || "").match(
        /^bytes\s+\*\/(\d+)$/i,
      );
      const total = match ? Number(match[1]) : 0;
      if (
        Number.isSafeInteger(total) &&
        total > 0 &&
        total === offset &&
        (!effectiveExpectedSize || total === effectiveExpectedSize)
      ) {
        onProgress({
          receivedBytes: offset,
          totalBytes: total,
          resumedBytes: offset,
          complete: true,
        });
        return {
          size: offset,
          totalBytes: total,
          resumedBytes: offset,
          rangeAccepted: true,
        };
      }
      removeDownloadState(filePath, metadataPath);
      throw new UserFacingError("下载断点已经失效，请重新开始安装");
    } else {
      throw new UserFacingError(`下载失败：HTTP ${response.status}`);
    }

    if (!response.ok || !response.body)
      throw new UserFacingError(`下载失败：HTTP ${response.status}`);
    if (totalBytes > maxBytes) {
      removeDownloadState(filePath, metadataPath);
      throw new UserFacingError("下载文件超过安全大小限制");
    }
    writeDownloadMetadata(metadataPath, {
      ...identity,
      totalBytes,
      etag: response.headers.get("etag") || metadata?.etag || "",
      lastModified:
        response.headers.get("last-modified") || metadata?.lastModified || "",
      responseUrl: response.url,
      updatedAt: new Date().toISOString(),
    });

    const fileDescriptor = fs.openSync(filePath, append ? "a" : "w");
    let receivedBytes = offset;
    const reader = response.body.getReader();
    try {
      while (true) {
        request.armTimeout(
          `下载连续 ${Math.round(DEPENDENCY_IDLE_TIMEOUT_MS / 1000)} 秒没有收到数据`,
          DEPENDENCY_IDLE_TIMEOUT_MS,
        );
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = Buffer.from(value);
        fs.writeSync(fileDescriptor, chunk);
        receivedBytes += chunk.length;
        if (
          receivedBytes > maxBytes ||
          (totalBytes > 0 && receivedBytes > totalBytes)
        ) {
          throw new UserFacingError("下载文件超过声明的安全大小限制");
        }
        onProgress({
          receivedBytes,
          totalBytes,
          resumedBytes: rangeAccepted ? requestedOffset : 0,
          rangeAccepted,
        });
      }
    } finally {
      fs.closeSync(fileDescriptor);
    }
    if (totalBytes > 0 && receivedBytes !== totalBytes) {
      throw new UserFacingError("下载连接提前结束，未完成文件已保留供下次续传");
    }
    writeDownloadMetadata(metadataPath, {
      ...identity,
      totalBytes: receivedBytes,
      etag: response.headers.get("etag") || metadata?.etag || "",
      lastModified:
        response.headers.get("last-modified") || metadata?.lastModified || "",
      responseUrl: response.url,
      updatedAt: new Date().toISOString(),
    });
    return {
      size: receivedBytes,
      totalBytes: receivedBytes,
      resumedBytes: rangeAccepted ? requestedOffset : 0,
      rangeAccepted,
    };
  } catch (error) {
    if (request.timeoutError())
      throw new UserFacingError(request.timeoutError());
    throw error;
  } finally {
    request.dispose();
  }
}

async function downloadOfficialNucleiTemplates(
  templatesDir,
  session,
  reportProgress = () => {},
) {
  reportProgress({ stage: "正在查询 Nuclei 模板版本", progress: 0 });
  const apiUrl =
    "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest";
  const releaseResponse = await fetchDependencyResource(apiUrl, {
    headers: githubApiHeaders(),
  });
  if (!releaseResponse.ok) {
    if (releaseResponse.status === 403 || releaseResponse.status === 429)
      throw githubApiError(releaseResponse);
    throw new UserFacingError(
      `查询 Nuclei 模板版本失败：HTTP ${releaseResponse.status}`,
    );
  }
  allowedResponseHost(releaseResponse, apiUrl, ["api.github.com"]);
  const release = await releaseResponse.json();
  if (release.draft || release.prerelease)
    throw new UserFacingError("Nuclei 模板最新版本不是稳定发布版");
  const tag = String(release.tag_name || "");
  const version = tag.replace(/^v/i, "");
  if (!/^\d+\.\d+\.\d+$/.test(version))
    throw new UserFacingError("Nuclei 模板版本号格式无法识别");
  const checksumName = `nuclei-templates-${version}_checksums.txt`;
  const checksumAssets = (
    Array.isArray(release.assets) ? release.assets : []
  ).filter(
    (asset) => asset?.name === checksumName && asset?.state === "uploaded",
  );
  if (checksumAssets.length !== 1)
    throw new UserFacingError("Nuclei 模板发布包缺少唯一校验文件");
  const checksumUrl = String(checksumAssets[0].browser_download_url || "");
  const checksumResponse = await fetchDependencyResource(checksumUrl);
  if (!checksumResponse.ok) {
    throw new UserFacingError(
      `下载 Nuclei 模板校验文件失败：HTTP ${checksumResponse.status}`,
    );
  }
  allowedResponseHost(checksumResponse, checksumUrl, [
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
  ]);
  const checksumText = await checksumResponse.text();
  if (checksumText.length > 64 * 1024)
    throw new UserFacingError("Nuclei 模板校验文件大小异常");
  const archiveName = `nuclei-templates-${version}.zip`;
  const checksumMatches = checksumText
    .split(/\r?\n/)
    .map((line) => line.trim().match(/^([a-f0-9]{64})\s+(.+)$/i))
    .filter((match) => match && match[2] === archiveName);
  if (checksumMatches.length !== 1) {
    throw new UserFacingError("官方校验文件中的模板压缩包记录不唯一");
  }
  const expectedSha256 = checksumMatches[0][1].toLowerCase();
  const installedMetadata = readJsonFile(
    path.join(templatesDir, ".toolbox-source.json"),
  );
  const installedState = evaluateInstalledRelease({
    metadata: installedMetadata,
    repository: "projectdiscovery/nuclei-templates",
    latestVersion: version,
    payloadExists: isRegularDirectory(templatesDir),
  });
  if (
    installedState.upToDate &&
    String(installedMetadata.archiveSha256 || "").toLowerCase() ===
      expectedSha256
  ) {
    reportProgress({ stage: "Nuclei 模板已是最新版本", progress: 1 });
    return { updated: false, version };
  }
  const sourceUrl = `https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${tag}.zip`;
  const downloadsDir = path.join(path.dirname(templatesDir), ".downloads");
  const archivePath = path.join(
    downloadsDir,
    `nuclei-templates-${version}-${expectedSha256.slice(0, 16)}.zip.part`,
  );
  const metadataPath = `${archivePath}.json`;
  [downloadsDir, archivePath, metadataPath].forEach((candidate) =>
    assertInside(path.dirname(templatesDir), candidate),
  );
  fs.mkdirSync(downloadsDir, { recursive: true });
  session.artifacts.add(JSON.stringify([archivePath, metadataPath]));
  session.phase = "downloading-templates";
  session.controller = new AbortController();
  await downloadResumableFile({
    url: sourceUrl,
    filePath: archivePath,
    metadataPath,
    expectedSha256,
    maxBytes: 250 * 1024 * 1024,
    allowedHosts: ["github.com", "codeload.github.com"],
    signal: session.controller.signal,
    onProgress: (progress) => {
      const receivedBytes = Number(progress.receivedBytes || 0);
      const totalBytes = Number(progress.totalBytes || 0);
      const fraction =
        totalBytes > 0 ? Math.min(1, receivedBytes / totalBytes) : 0;
      const stage = progress.restarted
        ? "模板下载源不支持续传，已从头重新下载"
        : progress.resumedBytes > 0
          ? `正在续传 Nuclei 官方模板（已恢复 ${Math.round((progress.resumedBytes / 1024 / 1024) * 10) / 10} MB）`
          : progress.complete
            ? "检测到完整的模板下载，正在校验"
            : "正在下载 Nuclei 官方签名模板";
      reportProgress({ ...progress, stage, progress: 0.05 + fraction * 0.45 });
    },
  });
  throwIfDependencyInterrupted(session);
  session.phase = "verifying-templates";
  session.controller = undefined;
  const stagingDir = path.join(
    path.dirname(templatesDir),
    `.nuclei-templates-${crypto.randomUUID()}`,
  );
  const backupDir = path.join(
    path.dirname(templatesDir),
    `.nuclei-templates-backup-${crypto.randomUUID()}`,
  );
  assertInside(path.dirname(templatesDir), stagingDir);
  assertInside(path.dirname(templatesDir), backupDir);
  fs.mkdirSync(stagingDir, { recursive: true });
  try {
    await runDependencyWorker(
      "extract-templates",
      {
        archivePath,
        expectedSha256,
        maxArchiveBytes: 250 * 1024 * 1024,
        stagingDir,
        maxFiles: 100000,
        maxExtractedBytes: 1024 * 1024 * 1024,
        sourceMetadata: {
          repository: "projectdiscovery/nuclei-templates",
          version: tag,
          archiveSha256: expectedSha256,
          sourceUrl,
          acquisition: "verified-release-archive",
          installedAt: new Date().toISOString(),
        },
      },
      (progress) =>
        reportProgress({
          ...progress,
          progress: 0.5 + Number(progress.progress || 0) * 0.5,
        }),
    );
    if (fs.existsSync(templatesDir)) fs.renameSync(templatesDir, backupDir);
    fs.renameSync(stagingDir, templatesDir);
    if (fs.existsSync(backupDir)) {
      try {
        await fs.promises.rm(backupDir, { recursive: true, force: true });
      } catch {
        // A stale backup is safer than failing a valid install.
      }
    }
    removeDownloadState(archivePath, metadataPath);
    return { updated: true, version };
  } catch (error) {
    if (
      /SHA-256|长度/.test(
        error instanceof Error ? error.message : String(error),
      )
    ) {
      removeDownloadState(archivePath, metadataPath);
    }
    if (fs.existsSync(stagingDir))
      await fs.promises.rm(stagingDir, { recursive: true, force: true });
    if (!fs.existsSync(templatesDir) && fs.existsSync(backupDir))
      fs.renameSync(backupDir, templatesDir);
    throw error;
  }
}

async function testEmbeddingConnection(payload) {
  const existing = resolvedAiSettings();
  const mode = normalizeAiEmbeddingConnectionMode(
    payload?.embeddingConnectionMode,
  );
  const chatBaseUrl = normalizeAiBaseUrl(payload?.baseUrl);
  const embeddingBaseUrl = normalizeAiEmbeddingBaseUrl(
    payload?.embeddingBaseUrl,
    chatBaseUrl,
  );
  const model = normalizeAiEmbeddingModel(payload?.embeddingModel);
  const connection = selectEmbeddingTestConnection({
    mode,
    submitted: {
      baseUrl: chatBaseUrl,
      embeddingBaseUrl,
      apiKey: payload?.apiKey,
      embeddingApiKey: payload?.embeddingApiKey,
    },
    existing: {
      baseUrl: existing.baseUrl,
      embeddingBaseUrl: existing.embeddingBaseUrl,
      apiKey: existing.apiKey,
      embeddingApiKey: existing.customEmbeddingApiKey,
    },
  });
  if (connection.requiresReplacementKey) {
    throw new UserFacingError(
      "向量 API 地址已变化，请填写新服务对应的向量 API Key 后再测试",
    );
  }
  const controller = new AbortController();
  const timeoutMs = 20000;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = { "Content-Type": "application/json" };
    if (connection.apiKey) {
      headers.Authorization = `Bearer ${connection.apiKey}`;
    }
    const response = await electronNet.fetch(
      `${aiRuntimeBaseUrl(connection.baseUrl)}/embeddings`,
      {
        method: "POST",
        headers,
        body: JSON.stringify({ model, input: ["连接测试"] }),
        signal: controller.signal,
      },
    );
    if (!response.ok) {
      throw new UserFacingError(
        `向量服务返回错误状态（HTTP ${response.status}）`,
      );
    }
    const body = await response.json();
    const vector = body?.data?.[0]?.embedding;
    if (!Array.isArray(vector) || !vector.length) {
      throw new UserFacingError("向量服务已响应，但没有返回有效向量");
    }
    return { ok: true, model, message: `向量连接成功（${vector.length} 维）` };
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new UserFacingError(`向量服务连接超时（${timeoutMs / 1000} 秒）`);
    }
    if (error instanceof UserFacingError) throw error;
    throw new UserFacingError(
      `向量服务连接失败：${error?.message || "请检查地址和服务状态"}`,
    );
  } finally {
    clearTimeout(timeout);
  }
}

function decryptStoredEmbeddingApiKey(settings = readDesktopSettings()) {
  const encrypted = settings.ai?.encryptedEmbeddingApiKey;
  if (!encrypted) return "";
  if (!safeStorage.isEncryptionAvailable()) {
    throw new UserFacingError("当前系统无法解密已保存的向量 API Key");
  }
  try {
    return safeStorage.decryptString(Buffer.from(encrypted, "base64"));
  } catch {
    throw new UserFacingError("已保存的向量 API Key 无法解密，请重新填写");
  }
}

function isRegularFile(filePath) {
  try {
    const stat = fs.lstatSync(filePath);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
}

function isRegularDirectory(directory) {
  try {
    const stat = fs.lstatSync(directory);
    return stat.isDirectory() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
}

async function downloadOfficialScannerPocs({
  packageId,
  release,
  toolsDir,
  session,
  reportProgress = () => {},
}) {
  const scannerLabel = { afrog: "Afrog", xray: "Xray" }[packageId];
  if (!scannerLabel) throw new UserFacingError("不支持下载该扫描器 PoC");
  const pocsDir = path.join(toolsDir, `${packageId}-pocs`);
  const downloadsDir = path.join(toolsDir, ".downloads");
  const identity = crypto
    .createHash("sha256")
    .update(`${release.repository}@${release.tag}:pocs`, "utf8")
    .digest("hex");
  const archivePath = path.join(
    downloadsDir,
    `${packageId}-pocs-${release.version}-${identity.slice(0, 16)}.zip.part`,
  );
  const metadataPath = `${archivePath}.json`;
  const sourceUrl = `https://github.com/${release.repository}/archive/refs/tags/${encodeURIComponent(release.tag)}.zip`;
  const installedMetadata = readJsonFile(
    path.join(pocsDir, ".toolbox-source.json"),
  );
  const installedState = evaluateInstalledRelease({
    metadata: installedMetadata,
    repository: release.repository,
    latestVersion: release.version,
    payloadExists: isRegularDirectory(pocsDir),
  });
  if (
    installedState.upToDate &&
    String(installedMetadata.ref || "") === String(release.tag || "")
  ) {
    reportProgress({
      stage: `${scannerLabel} PoC 已是最新版本`,
      progress: 1,
    });
    return { updated: false, version: release.version, path: pocsDir };
  }
  [pocsDir, downloadsDir, archivePath, metadataPath].forEach((candidate) =>
    assertInside(toolsDir, candidate),
  );
  fs.mkdirSync(downloadsDir, { recursive: true });
  session.artifacts.add(JSON.stringify([archivePath, metadataPath]));
  session.phase = "downloading-scanner-pocs";
  session.controller = new AbortController();
  await downloadResumableFile({
    url: sourceUrl,
    filePath: archivePath,
    metadataPath,
    expectedSha256: "",
    maxBytes: 250 * 1024 * 1024,
    allowedHosts: [
      "github.com",
      "codeload.github.com",
      "objects.githubusercontent.com",
    ],
    signal: session.controller.signal,
    onProgress: (progress) => {
      const total = Number(progress.totalBytes || 0);
      const received = Number(progress.receivedBytes || 0);
      reportProgress({
        ...progress,
        progress: total > 0 ? 0.05 + 0.45 * (received / total) : 0.05,
      });
    },
  });
  throwIfDependencyInterrupted(session);
  session.phase = "verifying-scanner-pocs";
  session.controller = undefined;
  const stagingDir = path.join(
    toolsDir,
    `.${packageId}-pocs-${crypto.randomUUID()}`,
  );
  const backupDir = path.join(
    toolsDir,
    `.${packageId}-pocs-backup-${crypto.randomUUID()}`,
  );
  assertInside(toolsDir, stagingDir);
  assertInside(toolsDir, backupDir);
  fs.mkdirSync(stagingDir, { recursive: true });
  try {
    await runDependencyWorker(
      "extract-scanner-pocs",
      {
        archivePath,
        maxArchiveBytes: 250 * 1024 * 1024,
        stagingDir,
        maxFiles: 10000,
        maxExtractedBytes: 512 * 1024 * 1024,
        sourceSubdirectory: "pocs",
        scannerLabel,
        sourceMetadata: {
          repository: release.repository,
          version: release.version,
          ref: release.tag,
          sourceUrl,
          acquisition: "official-release-tag-source-snapshot",
          installedAt: new Date().toISOString(),
        },
      },
      (progress) =>
        reportProgress({
          ...progress,
          progress: 0.5 + Number(progress.progress || 0) * 0.5,
        }),
    );
    if (fs.existsSync(pocsDir)) fs.renameSync(pocsDir, backupDir);
    fs.renameSync(stagingDir, pocsDir);
    if (fs.existsSync(backupDir)) {
      try {
        await fs.promises.rm(backupDir, { recursive: true, force: true });
      } catch {
        // A stale backup does not invalidate the newly promoted snapshot.
      }
    }
    removeDownloadState(archivePath, metadataPath);
    return { updated: true, version: release.version, path: pocsDir };
  } catch (error) {
    if (fs.existsSync(stagingDir))
      await fs.promises.rm(stagingDir, { recursive: true, force: true });
    if (!fs.existsSync(pocsDir) && fs.existsSync(backupDir))
      fs.renameSync(backupDir, pocsDir);
    throw error;
  }
}

function allowedResponseHost(response, fallbackUrl, allowedHosts) {
  const resolvedUrl =
    typeof response.url === "string" && response.url.startsWith("https://")
      ? response.url
      : fallbackUrl;
  const parsed = new URL(resolvedUrl);
  if (
    parsed.protocol !== "https:" ||
    !allowedHosts.includes(parsed.hostname.toLowerCase())
  ) {
    throw new UserFacingError("下载重定向到了未授权站点");
  }
}

function stableReleaseVersion(release) {
  if (!release || release.draft || release.prerelease) return undefined;
  const tag = String(release.tag_name || "");
  const version = tag.replace(/^v/i, "");
  if (!/^\d+\.\d+\.\d+$/.test(version)) return undefined;
  return { tag, version };
}

function matchingReleaseAssets(release, definition, version) {
  const assets = Array.isArray(release?.assets) ? release.assets : [];
  const archiveName = definition.assetName(version);
  const checksumName = definition.checksumName(version);
  const archiveMatches = assets.filter(
    (asset) => asset?.state === "uploaded" && asset?.name === archiveName,
  );
  const checksumMatches = assets.filter(
    (asset) => asset?.state === "uploaded" && asset?.name === checksumName,
  );
  return { archiveName, checksumName, archiveMatches, checksumMatches };
}

async function fetchOfficialPackageRelease(definition) {
  const listMode = definition.releaseMode === "latest-semver-match";
  const apiUrl = listMode
    ? `https://api.github.com/repos/${definition.repository}/releases?per_page=30`
    : `https://api.github.com/repos/${definition.repository}/releases/latest`;
  const response = await fetchDependencyResource(apiUrl, {
    headers: githubApiHeaders(),
  });
  if (!response.ok) throw githubApiError(response);
  allowedResponseHost(response, apiUrl, ["api.github.com"]);
  const payload = await response.json();
  if (!listMode) return payload;
  if (!Array.isArray(payload) || payload.length > 30)
    throw new UserFacingError("官方发布列表格式异常");
  const release = payload.find((candidate) => {
    const parsed = stableReleaseVersion(candidate);
    if (!parsed) return false;
    const matches = matchingReleaseAssets(
      candidate,
      definition,
      parsed.version,
    );
    return (
      matches.archiveMatches.length === 1 && matches.checksumMatches.length <= 1
    );
  });
  if (!release)
    throw new UserFacingError(
      "官方仓库中没有可安全安装的 Windows x64 稳定版本",
    );
  return release;
}

async function resolveLatestPackage(definition) {
  const cached = latestPackageCache.get(definition.id);
  if (cached && Date.now() - cached.cachedAt < 30 * 60 * 1000)
    return cached.value;

  const release = await fetchOfficialPackageRelease(definition);
  const parsedRelease = stableReleaseVersion(release);
  if (!parsedRelease)
    throw new UserFacingError("官方最新版本不是可识别的稳定发布版");
  const { tag, version } = parsedRelease;
  const { archiveName, archiveMatches, checksumMatches } =
    matchingReleaseAssets(release, definition, version);
  if (archiveMatches.length !== 1) {
    throw new UserFacingError("最新发布版缺少唯一的 Windows x64 安装包");
  }
  if (checksumMatches.length > 1)
    throw new UserFacingError("最新发布版的官方校验文件不唯一");
  const archiveAsset = archiveMatches[0];
  const checksumAsset = checksumMatches[0];
  if (
    !archiveAsset.browser_download_url ||
    Number(archiveAsset.size) < 1 ||
    Number(archiveAsset.size) > 150 * 1024 * 1024 ||
    (checksumAsset &&
      (Number(checksumAsset.size) < 1 ||
        Number(checksumAsset.size) > 2 * 1024 * 1024))
  ) {
    throw new UserFacingError("官方发布资源大小或地址异常");
  }
  for (const asset of [archiveAsset, checksumAsset].filter(Boolean)) {
    const parsed = new URL(String(asset.browser_download_url));
    if (
      parsed.protocol !== "https:" ||
      parsed.hostname !== "github.com" ||
      !parsed.pathname.startsWith(
        `/${definition.repository}/releases/download/${tag}/`,
      )
    ) {
      throw new UserFacingError("官方发布服务返回了未授权的资源地址");
    }
  }

  let sha256 =
    typeof archiveAsset.digest === "string" &&
    archiveAsset.digest.startsWith("sha256:")
      ? archiveAsset.digest.substring(7).toLowerCase()
      : "";
  let integritySource = sha256
    ? "github-release-asset-digest"
    : "local-sha256-record";
  if (checksumAsset) {
    const checksumUrl = String(checksumAsset.browser_download_url);
    const checksumText = await fetchDependencyText(checksumUrl, {
      maxBytes: 2 * 1024 * 1024,
      allowedHosts: [
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
      ],
    });
    const checksumMatchesInFile = checksumText
      .split(/\r?\n/)
      .map((line) => {
        const match = line.trim().match(/^([a-f0-9]{64})\s+(.+)$/i);
        if (!match) return undefined;
        const fileName = match[2]
          .trim()
          .replace(/^\*/, "")
          .replace(/\\/g, "/")
          .replace(/^\.\/+/, "");
        return fileName === archiveName ? match[1].toLowerCase() : undefined;
      })
      .filter(Boolean);
    if (checksumMatchesInFile.length !== 1) {
      throw new UserFacingError("官方校验文件中的安装包记录不唯一");
    }
    const checksumSha256 = checksumMatchesInFile[0];
    if (sha256 && sha256 !== checksumSha256) {
      throw new UserFacingError("GitHub 资源摘要与官方校验值不一致");
    }
    sha256 = checksumSha256;
    integritySource = "official-checksum-file";
  }
  if (sha256 && !/^[a-f0-9]{64}$/.test(sha256)) {
    throw new UserFacingError("官方 SHA-256 格式无法识别");
  }

  const value = {
    version,
    tag,
    repository: definition.repository,
    url: String(archiveAsset.browser_download_url),
    sha256,
    integritySource,
    archiveName,
    size: Number(archiveAsset.size),
  };
  latestPackageCache.set(definition.id, { cachedAt: Date.now(), value });
  return value;
}

async function refreshPortableDependencyCatalog({
  packageId,
  release,
  toolsDir,
  session,
  report,
  progressStart,
  progressSpan,
}) {
  if (packageId === "nuclei") {
    const templatesDir = path.join(toolsDir, "nuclei-templates");
    assertInside(toolsDir, templatesDir);
    report("正在检查 Nuclei 官方模板版本", progressStart, 0, 0, {
      progressDeterminate: false,
    });
    return downloadOfficialNucleiTemplates(
      templatesDir,
      session,
      (progress) => {
        const templateProgress = Math.max(
          0,
          Math.min(1, Number(progress.progress || 0)),
        );
        report(
          progress.stage || "正在更新 Nuclei 官方模板",
          progressStart + Math.round(templateProgress * progressSpan),
          Number(progress.receivedBytes || progress.processedBytes || 0),
          Number(progress.totalBytes || 0),
          {
            progressDeterminate:
              (Number(progress.totalBytes || 0) > 0 &&
                (typeof progress.receivedBytes === "number" ||
                  typeof progress.processedBytes === "number")) ||
              (Number(progress.totalFiles || 0) > 0 &&
                typeof progress.processedFiles === "number"),
            processedFiles: progress.processedFiles,
            totalFiles: progress.totalFiles,
            resumed: progress.resumedBytes > 0,
            resumedBytes: Number(progress.resumedBytes || 0),
            rangeAccepted: Boolean(progress.rangeAccepted),
          },
        );
      },
    );
  }
  if (packageId === "afrog" || packageId === "xray") {
    const scannerLabel = packageId === "afrog" ? "Afrog" : "Xray";
    report(`正在检查 ${scannerLabel} 官方 PoC 版本`, progressStart, 0, 0, {
      progressDeterminate: false,
    });
    return downloadOfficialScannerPocs({
      packageId,
      release,
      toolsDir,
      session,
      reportProgress: (progress) => {
        const pocProgress = Math.max(
          0,
          Math.min(1, Number(progress.progress || 0)),
        );
        report(
          progress.stage || `正在更新 ${scannerLabel} 官方 PoC`,
          progressStart + Math.round(pocProgress * progressSpan),
          Number(progress.receivedBytes || progress.processedBytes || 0),
          Number(progress.totalBytes || 0),
          {
            progressDeterminate:
              Number(progress.totalBytes || 0) > 0 ||
              Number(progress.totalFiles || 0) > 0,
            processedFiles: progress.processedFiles,
            totalFiles: progress.totalFiles,
          },
        );
      },
    });
  }
  return { updated: false };
}

async function installPortableDependency(
  packageId,
  options = {},
  reportProgress = () => {},
) {
  const definition = INSTALLABLE_PACKAGES[packageId];
  if (!definition) throw new UserFacingError("不支持安装该依赖");
  if (process.platform !== "win32" || process.arch !== "x64") {
    throw new UserFacingError("当前安装包仅支持 Windows x64");
  }
  const refreshCatalog = options?.refreshCatalog === true;
  const existing = activeInstalls.get(packageId);
  if (existing?.state === "paused") activeInstalls.delete(packageId);
  else if (existing) return existing.promise;

  const session = {
    packageId,
    state: "running",
    phase: "resolving",
    intent: undefined,
    controller: undefined,
    artifacts: new Set(),
    promise: undefined,
    lastProgress: undefined,
  };

  const operation = (async () => {
    const report = (
      stage,
      percent,
      receivedBytes = 0,
      totalBytes = 0,
      extra = {},
    ) => {
      const progress = {
        packageId,
        stage,
        installStage: stage,
        progress: percent,
        progressDeterminate: false,
        downloadedBytes: receivedBytes,
        totalBytes,
        installing: percent < 100,
        paused: false,
        canPause:
          session.phase === "downloading-package" ||
          session.phase === "downloading-templates" ||
          session.phase === "downloading-scanner-pocs",
        ...extra,
      };
      session.lastProgress = progress;
      reportProgress(progress);
    };
    report("正在查询官方最新版本", 1, 0, 0, { progressDeterminate: false });
    const release = await resolveLatestPackage(definition);
    const toolsDir = resolveToolsDirectory();
    const downloadsDir = path.join(toolsDir, ".downloads");
    const stagingRoot = path.join(toolsDir, ".staging");
    const stagingDir = path.join(
      stagingRoot,
      `${packageId}-${crypto.randomUUID()}`,
    );
    const targetDir = path.join(toolsDir, packageId);
    const releaseIdentity =
      release.sha256 ||
      crypto
        .createHash("sha256")
        .update(
          `${release.repository}@${release.tag}:${release.archiveName}`,
          "utf8",
        )
        .digest("hex");
    const archivePath = path.join(
      downloadsDir,
      `${packageId}-${release.version}-${releaseIdentity.slice(0, 16)}.zip.part`,
    );
    const archiveMetadataPath = `${archivePath}.json`;
    const stagedExecutable = path.join(stagingDir, definition.executable);
    const targetExecutable = path.join(targetDir, definition.executable);
    [
      downloadsDir,
      stagingRoot,
      stagingDir,
      targetDir,
      archivePath,
      archiveMetadataPath,
      stagedExecutable,
      targetExecutable,
    ].forEach((candidate) => assertInside(toolsDir, candidate));
    assertSafeInstallDirectory(toolsDir);
    assertSafeInstallDirectory(downloadsDir);
    assertSafeInstallDirectory(stagingRoot);
    assertSafeInstallDirectory(stagingDir);
    assertSafeInstallDirectory(targetDir);
    session.artifacts.add(JSON.stringify([archivePath, archiveMetadataPath]));

    let installationCompleted = false;
    let catalogUpdated = false;
    try {
      const installedMetadata = readJsonFile(
        path.join(targetDir, ".toolbox-source.json"),
      );
      const installedState = evaluateInstalledRelease({
        metadata: installedMetadata,
        repository: release.repository,
        latestVersion: release.version,
        payloadExists: isRegularFile(targetExecutable),
      });
      if (installedState.upToDate) {
        if (refreshCatalog) {
          const catalogResult = await refreshPortableDependencyCatalog({
            packageId,
            release,
            toolsDir,
            session,
            report,
            progressStart: 5,
            progressSpan: 94,
          });
          catalogUpdated = catalogResult.updated === true;
        }
        const stage = refreshCatalog
          ? catalogUpdated
            ? "工具已是最新版本，漏洞目录已更新"
            : "工具和漏洞目录已是最新版本"
          : "当前已是最新版本";
        report(stage, 100, 0, 0, { progressDeterminate: true });
        session.state = "completed";
        return {
          packageId,
          version: installedState.installedVersion,
          latestVersion: release.version,
          path: targetExecutable,
          toolsDirectory: toolsDir,
          status: "up-to-date",
          updated: false,
          catalogUpdated,
        };
      }
      report(`正在连接官方下载源（v${release.version}）`, 2, 0, 0, {
        progressDeterminate: false,
      });
      session.phase = "downloading-package";
      session.controller = new AbortController();
      const download = await downloadResumableFile({
        url: release.url,
        filePath: archivePath,
        metadataPath: archiveMetadataPath,
        expectedSha256: release.sha256,
        expectedSize: release.size,
        maxBytes: 150 * 1024 * 1024,
        allowedHosts: [
          "github.com",
          "release-assets.githubusercontent.com",
          "objects.githubusercontent.com",
        ],
        signal: session.controller.signal,
        onProgress: (progress) => {
          const receivedBytes = Number(progress.receivedBytes || 0);
          const totalBytes = Number(progress.totalBytes || release.size || 0);
          const downloadPercent =
            totalBytes > 0
              ? Math.min(
                  80,
                  Math.max(2, Math.round((receivedBytes / totalBytes) * 80)),
                )
              : Math.min(79, 2 + Math.floor(receivedBytes / (1024 * 1024)));
          const stage = progress.restarted
            ? "下载源不支持续传，已从头重新下载"
            : progress.resumedBytes > 0
              ? `正在续传安装包（已恢复 ${Math.round((progress.resumedBytes / 1024 / 1024) * 10) / 10} MB）`
              : progress.complete
                ? "检测到完整的未完成下载，正在校验"
                : "正在下载安装包";
          report(stage, downloadPercent, receivedBytes, totalBytes, {
            progressDeterminate: totalBytes > 0,
            resumed: progress.resumedBytes > 0,
            resumedBytes: Number(progress.resumedBytes || 0),
            rangeAccepted: Boolean(progress.rangeAccepted),
          });
        },
      });
      throwIfDependencyInterrupted(session);
      session.controller = undefined;
      session.phase = "verifying-package";
      try {
        const extraction = await runDependencyWorker(
          "extract-executable",
          {
            archivePath,
            expectedSha256: release.sha256,
            expectedSize: release.size,
            maxArchiveBytes: 150 * 1024 * 1024,
            executableName: definition.executable,
            targetPath: stagedExecutable,
            maxExecutableBytes: 256 * 1024 * 1024,
          },
          (progress) => {
            const workerProgress = Math.max(
              0,
              Math.min(1, Number(progress.progress || 0)),
            );
            if (workerProgress >= 0.74) session.phase = "extracting-package";
            const processedBytes = Number(progress.processedBytes || 0);
            const processedTotalBytes = Number(progress.totalBytes || 0);
            const progressDeterminate =
              (processedTotalBytes > 0 &&
                typeof progress.processedBytes === "number") ||
              (Number(progress.totalFiles || 0) > 0 &&
                typeof progress.processedFiles === "number");
            report(
              progress.stage || "正在后台处理安装包",
              81 + Math.round(workerProgress * 11),
              processedBytes,
              processedTotalBytes,
              {
                progressDeterminate,
                processedFiles: progress.processedFiles,
                totalFiles: progress.totalFiles,
                resumed: download.resumedBytes > 0,
                resumedBytes: download.resumedBytes,
                rangeAccepted: download.rangeAccepted,
              },
            );
          },
        );
        session.extraction = extraction;
      } catch (error) {
        if (
          /SHA-256|长度/.test(
            error instanceof Error ? error.message : String(error),
          )
        ) {
          removeDownloadState(archivePath, archiveMetadataPath);
        }
        throw error;
      }
      const catalogResult = await refreshPortableDependencyCatalog({
        packageId,
        release,
        toolsDir,
        session,
        report,
        progressStart: 93,
        progressSpan: 6,
      });
      catalogUpdated = catalogResult.updated === true;
      session.phase = "installing";
      report("正在原子替换工具文件", 99, 0, 0, { progressDeterminate: false });
      const recordedSha256 = String(
        session.extraction?.archiveSha256 || "",
      ).toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(recordedSha256)) {
        throw new UserFacingError("无法记录安装包 SHA-256，已拒绝安装");
      }
      promotePortableInstall({
        toolsDir,
        stagingDir,
        targetDir,
        stagedExecutable,
        targetExecutable,
        sourceMetadata: {
          repository: release.repository,
          version: release.version,
          releaseTag: release.tag,
          archiveName: release.archiveName,
          archiveSha256: recordedSha256,
          integritySource: release.integritySource,
          integrityVerified: Boolean(release.sha256),
          sourceUrl: release.url,
          platform: "windows",
          architecture: "x64",
          acquisition: "allowlisted-official-release",
          installedAt: new Date().toISOString(),
        },
      });
      installationCompleted = true;
      removeDownloadState(archivePath, archiveMetadataPath);
      report(
        "安装完成",
        100,
        download.size,
        download.totalBytes || download.size,
        { progressDeterminate: true },
      );
      session.state = "completed";
      return {
        packageId,
        version: release.version,
        latestVersion: release.version,
        path: targetExecutable,
        toolsDirectory: toolsDir,
        sha256: recordedSha256,
        integritySource: release.integritySource,
        updated: true,
        catalogUpdated,
      };
    } catch (error) {
      if (session.intent === "pause" || session.intent === "cancel") {
        const action = session.intent;
        session.controller = undefined;
        if (action === "cancel") {
          for (const artifact of session.artifacts)
            removeDownloadState(...JSON.parse(artifact));
          session.state = "canceled";
        } else session.state = "paused";
        const progress = {
          ...(session.lastProgress || {}),
          packageId,
          stage: action === "pause" ? "paused" : "canceled",
          installStage:
            action === "pause"
              ? "下载已暂停，断点文件已保留"
              : "下载已取消，缓存文件已清除",
          installing: false,
          paused: action === "pause",
          canPause: false,
        };
        session.lastProgress = progress;
        reportProgress(progress);
        return {
          packageId,
          status: action === "pause" ? "paused" : "canceled",
        };
      }
      session.state = "failed";
      const message = publicErrorMessage(
        error,
        "依赖安装失败，请检查网络和磁盘空间后重试",
      );
      if (!(error instanceof UserFacingError)) {
        writeDesktopStartupDiagnostic("dependency-install", error, {
          packageId,
          phase: session.phase,
        });
      }
      reportProgress({
        packageId,
        stage: "failed",
        installStage: message,
        progress: 0,
        progressDeterminate: false,
        downloadedBytes: 0,
        totalBytes: 0,
        installing: false,
      });
      throw new UserFacingError(message);
    } finally {
      if (installationCompleted)
        removeDownloadState(archivePath, archiveMetadataPath);
      assertInside(toolsDir, stagingDir);
      fs.rmSync(stagingDir, { recursive: true, force: true });
    }
  })();

  session.promise = operation;
  activeInstalls.set(packageId, session);
  try {
    return await operation;
  } finally {
    if (session.state !== "paused" && activeInstalls.get(packageId) === session)
      activeInstalls.delete(packageId);
  }
}

function portableDependencyInstallState(definition, toolsDir) {
  const targetDir = path.join(toolsDir, definition.id);
  const targetExecutable = path.join(targetDir, definition.executable);
  const metadata = readJsonFile(
    path.join(targetDir, ".toolbox-source.json"),
  );
  const state = evaluateInstalledRelease({
    metadata,
    repository: definition.repository,
    latestVersion: metadata.version,
    payloadExists: isRegularFile(targetExecutable),
  });
  return {
    ...state,
    metadata,
    targetDir,
    targetExecutable,
  };
}

async function uninstallPortableDependency(packageId) {
  const definition = INSTALLABLE_PACKAGES[packageId];
  if (!definition || definition.optional !== true) {
    throw new UserFacingError("只能卸载应用管理的可选依赖");
  }
  if (activeInstalls.has(packageId)) {
    throw new UserFacingError("该依赖正在更新，请等待完成或先取消下载");
  }
  const toolsDir = resolveToolsDirectory();
  const installed = portableDependencyInstallState(definition, toolsDir);
  assertInside(toolsDir, installed.targetDir);
  if (!installed.managed) {
    throw new UserFacingError("该依赖不是由本应用安装，无法在此卸载");
  }

  const removalDir = path.join(
    toolsDir,
    `.uninstall-${packageId}-${crypto.randomUUID()}`,
  );
  assertInside(toolsDir, removalDir);
  fs.renameSync(installed.targetDir, removalDir);
  try {
    await fs.promises.rm(removalDir, { recursive: true, force: true });
  } catch (error) {
    if (!fs.existsSync(installed.targetDir) && fs.existsSync(removalDir)) {
      fs.renameSync(removalDir, installed.targetDir);
    }
    throw error;
  }
  return {
    packageId,
    version: installed.installedVersion,
    status: "uninstalled",
  };
}

async function controlDependencyInstall(packageId, action) {
  if (!["pause", "cancel"].includes(action))
    throw new UserFacingError("不支持的下载控制操作");
  const session = activeInstalls.get(packageId);
  if (!session) throw new UserFacingError("当前没有可控制的依赖下载");
  if (action === "cancel" && session.state === "paused") {
    for (const artifact of session.artifacts)
      removeDownloadState(...JSON.parse(artifact));
    session.state = "canceled";
    activeInstalls.delete(packageId);
    return { packageId, status: "canceled" };
  }
  if (session.state !== "running")
    throw new UserFacingError("当前下载状态不允许此操作");
  if (
    !["downloading-package", "downloading-templates"].includes(session.phase)
  ) {
    throw new UserFacingError("当前正在校验、解压或安装，不能暂停或取消");
  }
  if (action === "cancel" || !session.intent) session.intent = action;
  session.controller?.abort();
  return session.promise;
}

function isTrustedMainRendererUrl(value) {
  try {
    const candidate = new URL(String(value || ""));
    const devUrl = process.env.TOOLBOX_DEV_URL;
    if (devUrl) {
      const expected = new URL(devUrl);
      return (
        candidate.protocol === expected.protocol &&
        candidate.hostname === expected.hostname &&
        candidate.port === expected.port
      );
    }
    if (candidate.protocol !== "file:") return false;
    const expectedEntry = path.resolve(app.getAppPath(), "dist", "index.html");
    return path.resolve(fileURLToPath(candidate)) === expectedEntry;
  } catch {
    return false;
  }
}

function isTrustedLocalFileUrl(value, expectedFile) {
  try {
    const candidate = new URL(String(value || ""));
    return (
      candidate.protocol === "file:" &&
      path.resolve(fileURLToPath(candidate)) === path.resolve(expectedFile)
    );
  } catch {
    return false;
  }
}

function assertMainRenderer(event) {
  const mainFrame =
    mainWindow && !mainWindow.isDestroyed()
      ? mainWindow.webContents.mainFrame
      : undefined;
  const sameMainFrame =
    event.senderFrame === mainFrame ||
    (Number.isInteger(event.senderFrame?.processId) &&
      Number.isInteger(event.senderFrame?.routingId) &&
      event.senderFrame.processId === mainFrame?.processId &&
      event.senderFrame.routingId === mainFrame?.routingId);
  if (
    !mainWindow ||
    mainWindow.isDestroyed() ||
    event.sender !== mainWindow.webContents ||
    !event.senderFrame ||
    !sameMainFrame ||
    !isTrustedMainRendererUrl(event.senderFrame.url)
  ) {
    throw new Error("不允许从当前窗口执行桌面操作");
  }
}

function assertDesktopLoginRenderer(event) {
  assertMainRenderer(event);
  let hash;
  try {
    hash = new URL(event.senderFrame.url).hash;
  } catch {
    throw new Error("无法确认桌面登录页面来源");
  }
  if (!/^#\/login(?:\?|$)/.test(hash)) {
    throw new Error("本机登录凭据只允许由桌面登录页面请求");
  }
}

function normalizeCaptureTargetUrl(value) {
  let raw = String(value || "").trim();
  if (!raw || raw === "about:blank") return "about:blank";
  if (raw.length > 2048)
    throw new UserFacingError("抓包浏览器目标地址不能超过 2048 个字符");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `http://${raw}`;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new UserFacingError("抓包浏览器目标地址格式不正确");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password
  ) {
    throw new UserFacingError(
      "抓包浏览器仅支持不含账号密码的 HTTP 或 HTTPS 地址",
    );
  }
  return parsed.toString();
}

function normalizeCaptureBrowserOptions(payload) {
  const proxyHost = String(payload?.proxyHost || "")
    .trim()
    .toLowerCase();
  if (!["127.0.0.1", "localhost", "::1"].includes(proxyHost)) {
    throw new UserFacingError("抓包浏览器只允许连接本机代理");
  }
  const proxyPort = Number(payload?.proxyPort);
  if (!Number.isInteger(proxyPort) || proxyPort < 19080 || proxyPort > 19120) {
    throw new UserFacingError("抓包浏览器代理端口必须在 19080-19120 范围");
  }
  const rawFingerprint = String(payload?.caFingerprint || "").trim();
  let caFingerprint;
  if (rawFingerprint) {
    const compactFingerprint = rawFingerprint.replace(/:/g, "");
    if (
      !/^[0-9a-f]{64}$/i.test(compactFingerprint) ||
      (rawFingerprint.includes(":") &&
        !/^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i.test(rawFingerprint))
    ) {
      throw new UserFacingError("抓包浏览器 CA 指纹必须是有效的 SHA-256 指纹");
    }
    caFingerprint = compactFingerprint.toUpperCase();
  }
  return {
    proxyHost,
    proxyPort,
    targetUrl: normalizeCaptureTargetUrl(payload?.targetUrl),
    caFingerprint,
  };
}

function normalizeCertificateFingerprint(value) {
  const normalized = String(value || "")
    .replace(/:/g, "")
    .trim()
    .toUpperCase();
  return /^[0-9A-F]{64}$/.test(normalized) ? normalized : undefined;
}

function rootCertificateFingerprint(certificate) {
  let current = certificate;
  const visited = new Set();
  for (let depth = 0; current && depth < 16; depth += 1) {
    const fingerprint = normalizeCertificateFingerprint(
      current.fingerprint256 || current.fingerprint,
    );
    const identity = `${fingerprint || ""}:${current.serialNumber || ""}`;
    if (visited.has(identity)) return fingerprint;
    visited.add(identity);
    if (!current.issuerCert) return fingerprint;
    const issuerFingerprint = normalizeCertificateFingerprint(
      current.issuerCert.fingerprint256 || current.issuerCert.fingerprint,
    );
    if (!issuerFingerprint || issuerFingerprint === fingerprint)
      return issuerFingerprint || fingerprint;
    current = current.issuerCert;
  }
  return undefined;
}

function configureCaptureCertificateTrust(captureSession, caFingerprint) {
  if (!caFingerprint) return;
  captureSession.setCertificateVerifyProc((request, callback) => {
    // This is a dedicated, isolated capture-browser session. The proxy's
    // locally generated leaf certificates must be accepted so Chromium can
    // complete the client-side TLS handshake and the server can decrypt it.
    // External applications are never affected by this exception.
    callback(0);
  });
}

function captureBrowserStatus() {
  return {
    running: Boolean(
      captureBrowserWindow && !captureBrowserWindow.isDestroyed(),
    ),
    proxyHost: captureBrowserConfig?.proxyHost,
    proxyPort: captureBrowserConfig?.proxyPort,
    targetUrl: captureBrowserConfig?.targetUrl,
    mitmTrusted: Boolean(captureBrowserConfig?.caFingerprint),
  };
}

async function disposeCaptureBrowserSession(sessionToDispose) {
  if (!sessionToDispose) return;
  sessionToDispose.setCertificateVerifyProc(null);
  await sessionToDispose.setProxy({ mode: "direct" }).catch(() => {});
  await sessionToDispose.closeAllConnections().catch(() => {});
  await sessionToDispose.clearStorageData().catch(() => {});
  await sessionToDispose.clearCache().catch(() => {});
}

function closeCaptureBrowser() {
  const windowToClose = captureBrowserWindow;
  const sessionToDispose = captureBrowserSession;
  captureBrowserWindow = undefined;
  captureBrowserSession = undefined;
  captureBrowserPartition = undefined;
  captureBrowserConfig = undefined;
  if (windowToClose && !windowToClose.isDestroyed()) windowToClose.close();
  void disposeCaptureBrowserSession(sessionToDispose);
  return captureBrowserStatus();
}

function isHttpNavigation(url) {
  if (url === "about:blank") return true;
  try {
    return ["http:", "https:"].includes(new URL(url).protocol);
  } catch {
    return false;
  }
}

async function launchCaptureBrowser(payload) {
  const options = normalizeCaptureBrowserOptions(payload);
  if (captureBrowserWindow && !captureBrowserWindow.isDestroyed())
    closeCaptureBrowser();

  const partition = `capture:security-toolbox-${crypto.randomUUID()}`;
  const captureSession = electronSession.fromPartition(partition, {
    cache: false,
  });
  configureCaptureCertificateTrust(captureSession, options.caFingerprint);
  const proxyEndpoint = `${options.proxyHost}:${options.proxyPort}`;
  await captureSession.setProxy({
    mode: "fixed_servers",
    proxyRules: `http=${proxyEndpoint};https=${proxyEndpoint}`,
    proxyBypassRules: "<-loopback>",
  });
  await captureSession.closeAllConnections();

  const captureTheme = currentSystemTheme();
  const captureWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 760,
    minHeight: 520,
    show: false,
    title: "獬豸抓包浏览器",
    backgroundColor: windowBackgroundColor(captureTheme),
    backgroundMaterial:
      captureTheme.transparencyEnabled && !captureTheme.highContrast
        ? captureTheme.windowMaterial
        : "none",
    autoHideMenuBar: false,
    webPreferences: {
      devTools: !app.isPackaged,
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webviewTag: true,
    },
  });

  captureBrowserWindow = captureWindow;
  captureBrowserSession = captureSession;
  captureBrowserPartition = partition;
  captureBrowserConfig = options;

  const captureShell = path.join(__dirname, "capture-browser.html");
  const guardCaptureShellNavigation = (event, url) => {
    if (!isTrustedLocalFileUrl(url, captureShell)) event.preventDefault();
  };
  captureWindow.webContents.on("will-navigate", guardCaptureShellNavigation);
  captureWindow.webContents.on("will-redirect", guardCaptureShellNavigation);

  captureWindow.webContents.on(
    "will-attach-webview",
    (event, webPreferences, params) => {
      if (params.partition !== partition || !isHttpNavigation(params.src)) {
        event.preventDefault();
        return;
      }
      webPreferences.nodeIntegration = false;
      webPreferences.nodeIntegrationInSubFrames = false;
      webPreferences.contextIsolation = true;
      webPreferences.sandbox = true;
      webPreferences.webSecurity = true;
      webPreferences.devTools = !app.isPackaged;
      delete webPreferences.preload;
    },
  );
  captureWindow.webContents.on("did-attach-webview", (_event, guest) => {
    guest.on("will-navigate", (navigationEvent, url) => {
      if (!isHttpNavigation(url)) navigationEvent.preventDefault();
    });
    guest.setWindowOpenHandler(({ url }) => {
      if (isHttpNavigation(url))
        setImmediate(() => {
          if (!guest.isDestroyed()) guest.loadURL(url);
        });
      return { action: "deny" };
    });
  });
  captureWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  captureWindow.on("closed", () => {
    if (captureBrowserWindow === captureWindow) {
      captureBrowserWindow = undefined;
      captureBrowserSession = undefined;
      captureBrowserPartition = undefined;
      captureBrowserConfig = undefined;
      void disposeCaptureBrowserSession(captureSession);
      if (mainWindow && !mainWindow.isDestroyed())
        mainWindow.webContents.send("toolbox:capture-browser-closed");
    }
  });
  captureWindow.once("ready-to-show", () => {
    applySystemThemeToStaticWindow(captureWindow);
    captureWindow.show();
  });
  try {
    await captureWindow.loadFile(captureShell, {
      query: { target: options.targetUrl, partition, proxy: proxyEndpoint },
    });
  } catch (error) {
    closeCaptureBrowser();
    throw error;
  }
  return captureBrowserStatus();
}

function handleRendererIpc(channel, handler) {
  ipcMain.handle(channel, async (event, ...args) => {
    try {
      return await handler(event, ...args);
    } catch (error) {
      const message = publicErrorMessage(error, "桌面操作失败，请稍后重试");
      if (!(error instanceof UserFacingError)) {
        writeDesktopStartupDiagnostic(`ipc:${channel}`, error);
      }
      throw new Error(message);
    }
  });
}

handleRendererIpc("toolbox:get-tools-directory", (event) => {
  assertMainRenderer(event);
  return resolveToolsDirectory();
});
handleRendererIpc("toolbox:get-system-theme", (event) => {
  assertMainRenderer(event);
  return currentSystemTheme();
});
handleRendererIpc("toolbox:get-mica-enabled", (event) => {
  assertMainRenderer(event);
  return readDesktopSettings().micaEnabled !== false;
});
handleRendererIpc("toolbox:set-mica-enabled", (event, enabled) => {
  assertMainRenderer(event);
  const settings = readDesktopSettings();
  writeDesktopSettings({ ...settings, micaEnabled: Boolean(enabled) });
  broadcastSystemTheme();
  return readDesktopSettings().micaEnabled !== false;
});
handleRendererIpc("toolbox:get-window-material", (event) => {
  assertMainRenderer(event);
  return configuredWindowMaterial();
});
handleRendererIpc("toolbox:window-minimize", (event) => {
  assertMainRenderer(event);
  mainWindow.minimize();
});
handleRendererIpc("toolbox:window-toggle-maximize", (event) => {
  assertMainRenderer(event);
  if (mainWindow.isMaximized()) mainWindow.unmaximize();
  else mainWindow.maximize();
  return mainWindow.isMaximized();
});
handleRendererIpc("toolbox:window-is-maximized", (event) => {
  assertMainRenderer(event);
  return mainWindow.isMaximized();
});
handleRendererIpc("toolbox:window-close", (event) => {
  assertMainRenderer(event);
  mainWindow.close();
});
handleRendererIpc("toolbox:set-window-material", (event, material) => {
  assertMainRenderer(event);
  if (!["none", "mica", "acrylic"].includes(material))
    throw new UserFacingError("不支持的窗口材质");
  const settings = readDesktopSettings();
  writeDesktopSettings({
    ...settings,
    windowMaterial: material,
    micaEnabled: material !== "none",
  });
  broadcastSystemTheme();
  return configuredWindowMaterial();
});
handleRendererIpc("toolbox:choose-tools-directory", async (event) => {
  assertMainRenderer(event);
  if (hasRunningInstalls())
    throw new UserFacingError("依赖正在安装，暂时不能切换目录");
  const result = await dialog.showOpenDialog(mainWindow || undefined, {
    title: "选择便携工具安装目录",
    defaultPath: resolveToolsDirectory(),
    properties: ["openDirectory", "createDirectory"],
  });
  if (result.canceled || !result.filePaths[0]) {
    const toolsDirectory = resolveToolsDirectory();
    return {
      changed: false,
      canceled: true,
      path: toolsDirectory,
      toolsDirectory,
    };
  }
  return changeToolsDirectory(result.filePaths[0]);
});
handleRendererIpc("toolbox:reset-tools-directory", async (event) => {
  assertMainRenderer(event);
  if (hasRunningInstalls())
    throw new UserFacingError("依赖正在安装，暂时不能切换目录");
  return changeToolsDirectory(defaultToolsDirectory());
});
handleRendererIpc("toolbox:list-installable-dependencies", (event) => {
  assertMainRenderer(event);
  const toolsDir = resolveToolsDirectory();
  return Object.values(INSTALLABLE_PACKAGES).map((definition) => {
    const installed = portableDependencyInstallState(definition, toolsDir);
    return {
      packageId: definition.id,
      version: installed.installedVersion || "latest",
      optional: definition.optional === true,
      uninstallSupported:
        definition.optional === true && installed.managed === true,
    };
  });
});
handleRendererIpc("toolbox:install-dependency", (event, packageId, options) => {
  assertMainRenderer(event);
  return installPortableDependency(
    String(packageId),
    { refreshCatalog: options?.refreshCatalog === true },
    (progress) => {
      if (!event.sender.isDestroyed())
        event.sender.send("toolbox:dependency-install-progress", progress);
    },
  );
});
handleRendererIpc("toolbox:control-dependency-install", (event, payload) => {
  assertMainRenderer(event);
  return controlDependencyInstall(
    String(payload?.packageId || ""),
    String(payload?.action || ""),
  );
});
handleRendererIpc("toolbox:uninstall-dependency", (event, packageId) => {
  assertMainRenderer(event);
  return uninstallPortableDependency(String(packageId));
});
handleRendererIpc("toolbox:get-ai-settings", (event) => {
  assertMainRenderer(event);
  return publicAiSettings();
});
handleRendererIpc("toolbox:get-icp-settings", (event) => {
  assertMainRenderer(event);
  return publicIcpSettings();
});
handleRendererIpc("toolbox:get-github-token-settings", (event) => {
  assertMainRenderer(event);
  return publicGithubTokenSettings();
});
handleRendererIpc("toolbox:save-github-token-settings", (event, payload) => {
  assertMainRenderer(event);
  return saveGithubTokenSettings(
    payload && typeof payload === "object" ? payload : {},
  );
});
handleRendererIpc("toolbox:get-desktop-login-credentials", (event) => {
  assertDesktopLoginRenderer(event);
  // Issuable more than once per launch so 本机安全凭据 and Windows Hello can both be used and
  // login can be retried; the request is already restricted to the trusted #/login renderer.
  const credentials = ensureDesktopCredentials();
  return {
    username: credentials.username,
    password: credentials.adminPassword,
  };
});
// Gate the local credential behind the operating system's Windows Hello (PIN / fingerprint /
// face). Electron has no built-in Hello API, so we drive WinRT UserConsentVerifier through
// Windows PowerShell 5.1 (which carries the WinRT projection); the script is passed as a
// UTF-16 -EncodedCommand to avoid any quoting/encoding pitfalls.
function verifyWindowsHello() {
  return new Promise((resolve) => {
    const script = [
      "$ErrorActionPreference='Stop'",
      "try {",
      "  Add-Type -AssemblyName System.Runtime.WindowsRuntime",
      "  $null=[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]",
      "  $asTask=([System.WindowsRuntimeSystemExtensions].GetMethods()|?{$_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'})[0]",
      "  function Await($op,$t){ $m=$asTask.MakeGenericMethod($t); $x=$m.Invoke($null,@($op)); $x.Wait(-1)|Out-Null; $x.Result }",
      "  $a=Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])",
      '  if ("$a" -ne \'Available\'){ Write-Output "UNAVAILABLE:$a"; exit 2 }',
      "  $r=Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('验证身份以登录獬豸授权安全测试平台')) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])",
      "  if (\"$r\" -eq 'Verified'){ Write-Output 'VERIFIED'; exit 0 } else { Write-Output \"DENIED:$r\"; exit 1 }",
      '} catch { Write-Output "ERR:$($_.Exception.Message)"; exit 3 }',
    ].join("\n");
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    let out = "";
    try {
      const child = spawn(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-STA",
          "-ExecutionPolicy",
          "Bypass",
          "-EncodedCommand",
          encoded,
        ],
        { windowsHide: true },
      );
      const timer = setTimeout(() => {
        try {
          child.kill();
        } catch {
          /* ignore */
        }
      }, 90000);
      child.stdout.on("data", (chunk) => {
        out += chunk.toString();
      });
      child.on("error", (error) => {
        clearTimeout(timer);
        writeDesktopStartupDiagnostic("windows-hello-start", error);
        resolve({
          available: false,
          verified: false,
          reason: "无法启动 Windows Hello 验证",
        });
      });
      child.on("close", () => {
        clearTimeout(timer);
        const text = out.trim();
        if (text.includes("VERIFIED"))
          resolve({ available: true, verified: true });
        else if (text.includes("UNAVAILABLE")) {
          resolve({
            available: false,
            verified: false,
            reason: "当前设备未启用 Windows Hello",
          });
        } else {
          if (text.startsWith("ERR:"))
            writeDesktopStartupDiagnostic("windows-hello-verify", text);
          resolve({
            available: true,
            verified: false,
            reason: "Windows Hello 验证未通过或已取消",
          });
        }
      });
    } catch (error) {
      writeDesktopStartupDiagnostic("windows-hello-start", error);
      resolve({
        available: false,
        verified: false,
        reason: "无法启动 Windows Hello 验证",
      });
    }
  });
}
handleRendererIpc("toolbox:desktop-login-with-hello", async (event) => {
  assertDesktopLoginRenderer(event);
  if (process.platform !== "win32") {
    return {
      verified: false,
      available: false,
      reason: "当前系统不支持 Windows Hello",
    };
  }
  const result = await verifyWindowsHello();
  if (!result.verified)
    return {
      verified: false,
      available: result.available,
      reason: result.reason,
    };
  const credentials = ensureDesktopCredentials();
  return {
    verified: true,
    credentials: {
      username: credentials.username,
      password: credentials.adminPassword,
    },
  };
});
// Keep account-password / 本机安全凭据 / Windows Hello consistent: when the user changes the
// login password in Settings, re-encrypt the local credential bundle with the new password so
// every login path uses the same password (and no login button silently stops working).
function updateDesktopAdminPassword(newPassword) {
  assertSecureDesktopStorage();
  const current = ensureDesktopCredentials();
  const updated = validatedDesktopCredentials({
    schemaVersion: DESKTOP_CREDENTIAL_SCHEMA_VERSION,
    username: "admin",
    adminPassword: String(newPassword),
    jwtSecret: current.jwtSecret,
    mitmCaPassword: current.mitmCaPassword,
  });
  const settings = readDesktopSettings();
  const security =
    settings.desktopSecurity && typeof settings.desktopSecurity === "object"
      ? settings.desktopSecurity
      : {};
  const encryptedCredentialBundle = safeStorage
    .encryptString(JSON.stringify(updated))
    .toString("base64");
  writeDesktopSettings({
    ...settings,
    desktopSecurity: {
      ...security,
      schemaVersion: DESKTOP_CREDENTIAL_SCHEMA_VERSION,
      encryptedCredentialBundle,
    },
  });
  desktopCredentials = updated;
}
handleRendererIpc(
  "toolbox:set-desktop-admin-password",
  (event, newPassword) => {
    assertMainRenderer(event);
    const pw = String(newPassword || "");
    if (pw.length < 8 || pw.length > 128)
      throw new UserFacingError("密码长度需为 8-128 位");
    updateDesktopAdminPassword(pw);
    return { updated: true };
  },
);
handleRendererIpc("toolbox:test-ai-settings", (event, payload) => {
  assertMainRenderer(event);
  return testAiConnection(payload);
});
handleRendererIpc("toolbox:test-embedding-settings", (event, payload) => {
  assertMainRenderer(event);
  return testEmbeddingConnection(payload);
});
handleRendererIpc("toolbox:save-ai-settings", (event, payload) => {
  assertMainRenderer(event);
  return serializeAiSettingsOperation(async () => {
    const previousSettings = readDesktopSettings();
    const nextSettings = updatedAiSettings(previousSettings, payload);
    writeDesktopSettings(nextSettings);
    try {
      await restartAiRuntimeAndBackend();
      return publicAiSettings(nextSettings);
    } catch (error) {
      writeDesktopSettings(previousSettings);
      await restartAiRuntimeAndBackend().catch(() => {});
      throw error;
    }
  });
});
handleRendererIpc("toolbox:clear-ai-api-key", (event, payload) => {
  assertMainRenderer(event);
  return serializeAiSettingsOperation(async () => {
    const previousSettings = readDesktopSettings();
    const nextSettings = updatedAiSettings(previousSettings, payload, {
      clearApiKey: true,
    });
    writeDesktopSettings(nextSettings);
    try {
      await restartAiRuntimeAndBackend();
      return publicAiSettings(nextSettings);
    } catch (error) {
      writeDesktopSettings(previousSettings);
      await restartAiRuntimeAndBackend().catch(() => {});
      throw error;
    }
  });
});
handleRendererIpc("toolbox:clear-embedding-api-key", (event, payload) => {
  assertMainRenderer(event);
  return serializeAiSettingsOperation(async () => {
    const previousSettings = readDesktopSettings();
    const nextSettings = updatedAiSettings(previousSettings, payload, {
      clearEmbeddingApiKey: true,
    });
    writeDesktopSettings(nextSettings);
    try {
      await restartAiRuntimeAndBackend();
      return publicAiSettings(nextSettings);
    } catch (error) {
      writeDesktopSettings(previousSettings);
      await restartAiRuntimeAndBackend().catch(() => {});
      throw error;
    }
  });
});
handleRendererIpc("toolbox:save-icp-settings", (event, payload) => {
  assertMainRenderer(event);
  return serializeAiSettingsOperation(async () => {
    const previousSettings = readDesktopSettings();
    const nextSettings = updatedIcpSettings(previousSettings, payload);
    writeDesktopSettings(nextSettings);
    try {
      await restartBackend();
      return publicIcpSettings(nextSettings);
    } catch (error) {
      writeDesktopSettings(previousSettings);
      await restartBackend().catch(() => {});
      throw error;
    }
  });
});
handleRendererIpc("toolbox:clear-icp-settings", (event) => {
  assertMainRenderer(event);
  return serializeAiSettingsOperation(async () => {
    const previousSettings = readDesktopSettings();
    const nextSettings = updatedIcpSettings(previousSettings, undefined, true);
    writeDesktopSettings(nextSettings);
    try {
      await restartBackend();
      return publicIcpSettings(nextSettings);
    } catch (error) {
      writeDesktopSettings(previousSettings);
      await restartBackend().catch(() => {});
      throw error;
    }
  });
});
handleRendererIpc("toolbox:launch-capture-browser", (event, payload) => {
  assertMainRenderer(event);
  return launchCaptureBrowser(payload);
});
handleRendererIpc("toolbox:close-capture-browser", (event) => {
  assertMainRenderer(event);
  return closeCaptureBrowser();
});
handleRendererIpc("toolbox:get-capture-browser-status", (event) => {
  assertMainRenderer(event);
  return captureBrowserStatus();
});

const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) app.quit();

function resolveJava() {
  if (process.env.JAVA_HOME) {
    const candidate = path.join(
      process.env.JAVA_HOME,
      "bin",
      process.platform === "win32" ? "java.exe" : "java",
    );
    if (fs.existsSync(candidate)) return candidate;
  }
  // Let the real backend process perform PATH resolution. Its error listener
  // preserves startup diagnostics without launching a throwaway JVM first.
  return "java";
}

function resolveServerJar() {
  const candidate = app.isPackaged
    ? path.join(process.resourcesPath, "server", "security-toolbox-server.jar")
    : path.resolve(
        __dirname,
        "..",
        "..",
        "security-toolbox-server",
        "target",
        "security-toolbox-server-0.1.0.jar",
      );
  if (!fs.existsSync(candidate))
    throw new Error(`未找到后端服务文件：${candidate}`);
  return candidate;
}

async function findFreePort(start = 18080, end = 18120) {
  for (let port = start; port <= end; port += 1) {
    const free = await new Promise((resolve) => {
      const server = net.createServer();
      server.once("error", () => resolve(false));
      server.once("listening", () => server.close(() => resolve(true)));
      server.listen(port, "127.0.0.1");
    });
    if (free) return port;
  }
  throw new Error(`没有可用的本地服务端口（${start}-${end}）。`);
}

function updateStartup(title, message, error) {
  if (!startupWindow || startupWindow.isDestroyed()) return;
  const args = [title, message || "", error || ""]
    .map((value) => JSON.stringify(value))
    .join(",");
  startupWindow.webContents
    .executeJavaScript(`window.setStartupStatus(${args})`)
    .catch(() => {});
}

function waitForBackend(port, timeoutMs = 90000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const check = () => {
      const request = http.get(
        `http://127.0.0.1:${port}/api/system/health`,
        (response) => {
          const chunks = [];
          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () => {
            if (response.statusCode !== 200) return retry();
            try {
              resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
            } catch {
              retry();
            }
          });
        },
      );
      request.setTimeout(35000, () => request.destroy());
      request.on("error", retry);
    };
    const retry = () => {
      if (backendStartError) return reject(backendStartError);
      if (Date.now() >= deadline)
        return reject(new Error("本地服务启动超时，请查看桌面日志。"));
      setTimeout(check, 500);
    };
    check();
  });
}

const AI_RUNTIME_MIN_PYTHON = Object.freeze([3, 11]);
const AI_RUNTIME_PYTHON_MODULES = Object.freeze([
  "fastapi",
  "uvicorn",
  "pydantic",
  "httpx",
  "langchain_core",
  "langchain_openai",
  "langgraph",
  "rank_bm25",
]);

function inspectAiRuntimePython(candidate) {
  const probe = [
    "import importlib.util,json,struct,sys",
    `modules=${JSON.stringify(AI_RUNTIME_PYTHON_MODULES)}`,
    "missing=[name for name in modules if importlib.util.find_spec(name) is None]",
    "print(json.dumps({'major':sys.version_info.major,'minor':sys.version_info.minor,'bits':struct.calcsize('P')*8,'implementation':sys.implementation.name,'missing':missing}))",
  ].join(";");
  const result = spawnSync(candidate.command, [...candidate.args, "-c", probe], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 10000,
  });
  if (result.status !== 0) return undefined;
  try {
    const info = JSON.parse(String(result.stdout || "").trim().split(/\r?\n/).at(-1));
    const compatibleVersion =
      info.major > AI_RUNTIME_MIN_PYTHON[0] ||
      (info.major === AI_RUNTIME_MIN_PYTHON[0] &&
        info.minor >= AI_RUNTIME_MIN_PYTHON[1]);
    if (
      info.implementation !== "cpython" ||
      info.bits !== 64 ||
      !compatibleVersion ||
      !Array.isArray(info.missing) ||
      info.missing.length
    )
      return undefined;
    return { ...candidate, major: info.major, minor: info.minor };
  } catch {
    return undefined;
  }
}

function discoverAiRuntimePython(runtimeRoot) {
  const projectPython =
    process.platform === "win32"
      ? path.join(runtimeRoot, ".venv", "Scripts", "python.exe")
      : path.join(runtimeRoot, ".venv", "bin", "python");
  if (fs.existsSync(projectPython)) {
    const projectCandidate = inspectAiRuntimePython({
      command: projectPython,
      args: [],
      source: "ai-runtime/.venv",
    });
    if (projectCandidate) return projectCandidate;
  }

  const candidates = [];
  const seen = new Set();
  const addPath = (candidatePath, source) => {
    if (!candidatePath || !fs.existsSync(candidatePath)) return;
    const resolved = path.resolve(candidatePath);
    const key = resolved.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({ command: resolved, args: [], source });
  };
  const addCommand = (command, source) => {
    const key = `command:${command.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({ command, args: [], source });
  };

  for (const environmentRoot of [
    process.env.VIRTUAL_ENV,
    process.env.CONDA_PREFIX,
  ]) {
    if (!environmentRoot) continue;
    addPath(
      process.platform === "win32"
        ? path.join(environmentRoot, "python.exe")
        : path.join(environmentRoot, "bin", "python"),
      "active environment",
    );
  }
  addCommand("python", "PATH");

  if (process.platform === "win32") {
    const condaCommand = process.env.CONDA_EXE || "conda";
    const conda = spawnSync(condaCommand, ["env", "list", "--json"], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 10000,
    });
    if (conda.status === 0) {
      try {
        for (const environmentRoot of JSON.parse(conda.stdout).envs || [])
          addPath(path.join(environmentRoot, "python.exe"), "Conda environment");
      } catch {
        // Ignore malformed third-party Conda output and continue discovery.
      }
    }

    const launcher = spawnSync("py", ["-0p"], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 10000,
    });
    if (launcher.status === 0) {
      for (const line of String(launcher.stdout || "").split(/\r?\n/)) {
        const match = line.match(/([A-Za-z]:\\.*?python(?:\.exe)?)\s*$/i);
        if (match) addPath(match[1].trim(), "Python Launcher");
      }
    }
  } else {
    addCommand("python3", "PATH");
  }

  return candidates
    .map(inspectAiRuntimePython)
    .filter(Boolean)
    .sort((left, right) => left.major - right.major || left.minor - right.minor)[0];
}

function resolveAiRuntimeLaunch() {
  const runtimeRoot = app.isPackaged
    ? path.join(process.resourcesPath, "ai-runtime")
    : path.resolve(__dirname, "..", "..", "ai-runtime");
  const executableName =
    process.platform === "win32"
      ? "security-toolbox-ai-runtime.exe"
      : "security-toolbox-ai-runtime";
  const packagedExecutable = app.isPackaged
    ? path.join(runtimeRoot, executableName)
    : path.join(
        runtimeRoot,
        "dist",
        "security-toolbox-ai-runtime",
        executableName,
      );
  const configuredExecutable = String(
    process.env.AI_RUNTIME_EXECUTABLE || "",
  ).trim();
  if (configuredExecutable) {
    const candidate = path.resolve(configuredExecutable);
    if (!fs.existsSync(candidate))
      throw new Error(`AI Runtime 可执行文件不存在：${candidate}`);
    return { command: candidate, args: [], cwd: path.dirname(candidate) };
  }
  if (app.isPackaged) {
    if (!fs.existsSync(packagedExecutable))
      throw new Error(`安装包缺少 AI Runtime：${packagedExecutable}`);
    return { command: packagedExecutable, args: [], cwd: runtimeRoot };
  }

  const preferSourceRuntime =
    String(process.env.AI_RUNTIME_DEV_SOURCE || "").toLowerCase() === "true";
  if (!preferSourceRuntime && fs.existsSync(packagedExecutable)) {
    return {
      command: packagedExecutable,
      args: [],
      cwd: path.dirname(packagedExecutable),
    };
  }

  const sourceEntrypoint = path.join(runtimeRoot, "runtime_server.py");
  if (fs.existsSync(sourceEntrypoint)) {
    const python = discoverAiRuntimePython(runtimeRoot);
    if (python) {
      return {
        command: python.command,
        args: [...python.args, sourceEntrypoint],
        cwd: runtimeRoot,
      };
    }
  }
  if (fs.existsSync(packagedExecutable))
    return { command: packagedExecutable, args: [], cwd: runtimeRoot };
  throw new Error("未找到可用的 AI Runtime 或 Python 运行环境");
}

function aiRuntimeBaseUrl(baseUrl) {
  return `${String(baseUrl || "").replace(/\/+$/, "")}/v1`;
}

function writeAiRuntimeDiagnostic(error) {
  try {
    const logDir = path.join(app.getPath("userData"), "logs");
    fs.mkdirSync(logDir, { recursive: true });
    const message = diagnosticError(error);
    fs.appendFileSync(
      path.join(logDir, "ai-runtime-startup.log"),
      `${new Date().toISOString()} ${message.replace(/[\r\n]+/g, " ").slice(0, 2000)}\n`,
      "utf8",
    );
  } catch {
    // Diagnostics must never prevent the desktop application from starting.
  }
}

function writeDesktopStartupDiagnostic(stage, error, context = {}) {
  try {
    const logDir = path.join(app.getPath("userData"), "logs");
    fs.mkdirSync(logDir, { recursive: true });
    const message = diagnosticError(error);
    const record = {
      timestamp: new Date().toISOString(),
      stage,
      message: message.replace(/[\r\n]+/g, " ").slice(0, 2000),
      ...context,
    };
    fs.appendFileSync(
      path.join(logDir, "desktop-startup.log"),
      `${JSON.stringify(record)}\n`,
      "utf8",
    );
  } catch {
    // 诊断日志写入失败不能阻断桌面应用启动。
  }
}

function waitForAiRuntime(port, timeoutMs = 90000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const check = () => {
      const request = http.get(
        { hostname: "127.0.0.1", port, path: "/health", timeout: 2000 },
        (response) => {
          const chunks = [];
          let size = 0;
          response.on("data", (chunk) => {
            size += chunk.length;
            if (size <= 256 * 1024) chunks.push(chunk);
            else request.destroy(new Error("AI Runtime 健康响应大小异常"));
          });
          response.on("end", () => {
            if (response.statusCode !== 200) return retry();
            try {
              const health = JSON.parse(Buffer.concat(chunks).toString("utf8"));
              const components = health?.components || {};
              if (
                health?.agent?.graphCompiled !== true ||
                components.langchain !== true ||
                components.langgraph !== true ||
                components.llamaIndex !== true
              ) {
                return reject(
                  new Error(
                    "AI Runtime 依赖或 Planner–Executor–Reviewer 图未就绪",
                  ),
                );
              }
              resolve(health);
            } catch (error) {
              if (error instanceof SyntaxError) retry();
              else reject(error);
            }
          });
        },
      );
      request.on("timeout", () => request.destroy());
      request.on("error", retry);
    };
    const retry = () => {
      if (aiRuntimeStartError) return reject(aiRuntimeStartError);
      if (aiRuntimeProcess && aiRuntimeProcess.exitCode !== null) {
        return reject(
          new Error(`AI Runtime 已退出（代码 ${aiRuntimeProcess.exitCode}）`),
        );
      }
      if (Date.now() >= deadline)
        return reject(new Error("AI Runtime 启动超时，已切换为兼容模式"));
      setTimeout(check, 400);
    };
    check();
  });
}

async function startAiRuntime() {
  const spawned = await spawnAiRuntime();
  return waitForAiRuntimeReady(spawned.port);
}

async function spawnAiRuntime(slot) {
  aiRuntimeStartError = undefined;
  aiRuntimeSpawn = undefined;
  const resolved = slot ?? (await allocateAiRuntimeSlot());
  return launchAiRuntimeProcess(resolved);
}

async function allocateAiRuntimeSlot() {
  aiRuntimeStartError = undefined;
  const launch = resolveAiRuntimeLaunch();
  const port = await findFreePort(18121, 18180);
  const userDataDir = app.getPath("userData");
  const runtimeDataDir = path.join(userDataDir, "ai-runtime");
  const logDir = path.join(userDataDir, "logs");
  fs.mkdirSync(runtimeDataDir, { recursive: true });
  fs.mkdirSync(logDir, { recursive: true });

  const token = crypto.randomBytes(32).toString("base64url");
  const signingSecret = crypto.randomBytes(32).toString("base64url");
  const tokenFile = path.join(runtimeDataDir, "runtime-token.txt");
  const signingSecretFile = path.join(
    runtimeDataDir,
    "runtime-project-signing-secret.txt",
  );
  const temporaryTokenFile = `${tokenFile}.${process.pid}.tmp`;
  const temporarySigningSecretFile = `${signingSecretFile}.${process.pid}.tmp`;
  fs.writeFileSync(temporaryTokenFile, token, {
    encoding: "utf8",
    mode: 0o600,
  });
  if (fs.existsSync(tokenFile)) fs.unlinkSync(tokenFile);
  fs.renameSync(temporaryTokenFile, tokenFile);
  fs.writeFileSync(temporarySigningSecretFile, signingSecret, {
    encoding: "utf8",
    mode: 0o600,
  });
  if (fs.existsSync(signingSecretFile)) fs.unlinkSync(signingSecretFile);
  fs.renameSync(temporarySigningSecretFile, signingSecretFile);
  try {
    fs.chmodSync(tokenFile, 0o600);
    fs.chmodSync(signingSecretFile, 0o600);
  } catch {
    /* Windows ACL is inherited from userData. */
  }
  aiRuntimeTokenFile = tokenFile;
  aiRuntimeSigningSecretFile = signingSecretFile;
  return { port, token, tokenFile, signingSecret, signingSecretFile, launch };
}

function launchAiRuntimeProcess(slot) {
  const { port, token, tokenFile, signingSecret, signingSecretFile, launch } = slot;
  const userDataDir = app.getPath("userData");
  const runtimeDataDir = path.join(userDataDir, "ai-runtime");
  const logDir = path.join(userDataDir, "logs");
  fs.mkdirSync(runtimeDataDir, { recursive: true });
  fs.mkdirSync(logDir, { recursive: true });

  const aiSettings = resolvedAiSettings();
  const stdout = fs.openSync(path.join(logDir, "ai-runtime.out.log"), "a");
  const stderr = fs.openSync(path.join(logDir, "ai-runtime.err.log"), "a");
  const child = spawn(
    launch.command,
    [
      ...launch.args,
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--data-dir",
      runtimeDataDir,
      "--token-file",
      tokenFile,
      "--project-signing-secret-file",
      signingSecretFile,
      "--log-level",
      "warning",
    ],
    {
      cwd: launch.cwd,
      env: {
        ...process.env,
        AI_RUNTIME_LLM_ENABLED: String(
          Boolean(aiSettings.enabled && aiSettings.apiKey),
        ),
        AI_RUNTIME_API_KEY: aiSettings.apiKey,
        AI_RUNTIME_BASE_URL: aiRuntimeBaseUrl(aiSettings.baseUrl),
        AI_RUNTIME_MODEL: aiSettings.model,
        AI_RUNTIME_RETRIEVAL_BACKEND: aiSettings.retrievalBackend,
        AI_RUNTIME_EMBEDDING_BASE_URL: aiRuntimeBaseUrl(
          aiSettings.effectiveEmbeddingBaseUrl,
        ),
        AI_RUNTIME_EMBEDDING_API_KEY: aiSettings.effectiveEmbeddingApiKey,
        AI_RUNTIME_EMBEDDING_MODEL: aiSettings.embeddingModel,
      },
      stdio: ["ignore", stdout, stderr],
      windowsHide: true,
    },
  );
  fs.closeSync(stdout);
  fs.closeSync(stderr);
  aiRuntimeProcess = child;
  child.once("error", (error) => {
    aiRuntimeStartError = new Error(`无法启动 AI Runtime：${error.message}`);
  });
  child.once("exit", (code) => {
    if (aiRuntimeProcess === child) {
      if (!aiRuntimeConfig && !quitting) {
        aiRuntimeStartError = new Error(
          `AI Runtime 已退出（代码 ${code ?? "unknown"}）`,
        );
      }
      aiRuntimeProcess = undefined;
      aiRuntimeConfig = undefined;
    }
    if (!quitting && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("ai-runtime-exited", code);
    }
  });

  aiRuntimeSpawn = { port, token, signingSecret };
  return aiRuntimeSpawn;
}
async function waitForAiRuntimeReady(port) {
  const health = await waitForAiRuntime(port);
  aiRuntimeConfig = {
    url: `http://127.0.0.1:${port}`,
    port,
    token: aiRuntimeSpawn?.token,
    signingSecret: aiRuntimeSpawn?.signingSecret,
    health,
  };
  return aiRuntimeConfig;
}

function stopAiRuntime() {
  const child = aiRuntimeProcess;
  aiRuntimeProcess = undefined;
  aiRuntimeSpawn = undefined;
  aiRuntimeConfig = undefined;
  if (child && child.exitCode === null && Number.isInteger(child.pid)) {
    if (process.platform === "win32") {
      terminateWindowsProcessTree(child.pid, "AI Runtime");
    } else {
      child.kill("SIGTERM");
    }
  }
  if (aiRuntimeTokenFile) {
    try {
      fs.unlinkSync(aiRuntimeTokenFile);
    } catch {
      /* It may already be absent. */
    }
    aiRuntimeTokenFile = undefined;
  }
  if (aiRuntimeSigningSecretFile) {
    try {
      fs.unlinkSync(aiRuntimeSigningSecretFile);
    } catch {
      /* It may already be absent. */
    }
    aiRuntimeSigningSecretFile = undefined;
  }
}

function dependencySummary(result) {
  const dependencies = Array.isArray(result?.dependencies)
    ? result.dependencies
    : [];
  const available = dependencies.filter(
    (item) => item?.status === "AVAILABLE",
  ).length;
  const required = dependencies.filter((item) => item?.required);
  const requiredAvailable = required.filter(
    (item) => item?.status === "AVAILABLE",
  ).length;
  return `核心依赖 ${requiredAvailable}/${required.length} 可用，全部工具 ${available}/${dependencies.length} 可用。`;
}

function startBackend(java, jar, port, runtime = aiRuntimeSpawn) {
  backendStartError = undefined;
  const credentials = ensureDesktopCredentials();
  shutdownToken = shutdownToken || crypto.randomBytes(32).toString("hex");
  const userDataDir = app.getPath("userData");
  const dataDir = path.join(userDataDir, "data");
  const logDir = path.join(userDataDir, "logs");
  const toolsDir = resolveToolsDirectory();
  const aiSettings = resolvedAiSettings();
  const icpSettings = resolvedIcpSettings();
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(logDir, { recursive: true });
  try {
    fs.mkdirSync(toolsDir, { recursive: true });
  } catch {
    // The application can still start from a read-only install directory;
    // portable installation will report the write-permission error on demand.
  }
  const stdout = fs.openSync(path.join(logDir, "server.out.log"), "a");
  const stderr = fs.openSync(path.join(logDir, "server.err.log"), "a");
  const databasePath = path
    .join(dataDir, "security-toolbox")
    .replace(/\\/g, "/");
  cleanupStaleH2Lock(dataDir);
  const backendEnv = {
    ...process.env,
    TOOLBOX_DESKTOP: "true",
    TOOLBOX_DESKTOP_SYNC_ADMIN_PASSWORD: "true",
    ALLOW_INSECURE_DEVELOPMENT_CREDENTIALS: "false",
    TOOLBOX_SHUTDOWN_TOKEN: shutdownToken,
    TOOLBOX_TOOLS_DIR: toolsDir,
    ADMIN_PASSWORD: credentials.adminPassword,
    JWT_SECRET: credentials.jwtSecret,
    TRAFFIC_MITM_CA_PATH: desktopMitmCaPath(),
    TRAFFIC_MITM_CA_PASSWORD: credentials.mitmCaPassword,
    AI_BASE_URL: aiSettings.baseUrl,
    AI_API_KEY: aiSettings.apiKey,
    AI_ENABLED: String(aiSettings.enabled),
    AI_API_MODE: aiSettings.apiMode,
    AI_TIMEOUT_SECONDS: aiSettings.apiMode === "responses" ? "0" : "60",
    AI_MODEL: aiSettings.model,
    AI_RUNTIME_ENABLED: String(Boolean(runtime)),
    AI_RUNTIME_URL: runtime?.url || "",
    AI_RUNTIME_PORT: runtime?.port ? String(runtime.port) : "",
    AI_RUNTIME_TOKEN: runtime?.token || "",
    AI_RUNTIME_PROJECT_SIGNING_SECRET: runtime?.signingSecret || "",
    ICP_API_URL: icpSettings.apiUrl,
    NUCLEI_PATH: fs.existsSync(path.join(toolsDir, "nuclei", "nuclei.exe"))
      ? path.join(toolsDir, "nuclei", "nuclei.exe")
      : "nuclei",
    NUCLEI_TEMPLATES_PATH: path.join(toolsDir, "nuclei-templates"),
    HTTPX_PATH: fs.existsSync(path.join(toolsDir, "httpx", "httpx.exe"))
      ? path.join(toolsDir, "httpx", "httpx.exe")
      : "httpx",
    AFROG_PATH: fs.existsSync(path.join(toolsDir, "afrog", "afrog.exe"))
      ? path.join(toolsDir, "afrog", "afrog.exe")
      : "afrog",
    AFROG_POCS_PATH: path.join(toolsDir, "afrog-pocs"),
    XRAY_PATH: fs.existsSync(
      path.join(toolsDir, "xray", "xray_windows_amd64.exe"),
    )
      ? path.join(toolsDir, "xray", "xray_windows_amd64.exe")
      : "xray",
    XRAY_POCS_PATH: path.join(toolsDir, "xray-pocs"),
    PATH: [
      path.join(toolsDir, "nuclei"),
      path.join(toolsDir, "httpx"),
      path.join(toolsDir, "afrog"),
      path.join(toolsDir, "xray"),
      path.join(toolsDir, "nmap"),
      process.env.PATH || "",
    ].join(path.delimiter),
  };
  const explicitNmapPath = String(process.env.NMAP_PATH || "").trim();
  if (explicitNmapPath) {
    backendEnv.NMAP_PATH = process.env.NMAP_PATH;
  } else {
    const portableNmapPath = resolvePortableNmapPath(toolsDir);
    if (portableNmapPath) backendEnv.NMAP_PATH = portableNmapPath;
    else delete backendEnv.NMAP_PATH;
  }
  const child = spawn(
    java,
    [
  // Desktop-only JVM tuning. Stop tiered compilation at C1 to cut cold
  // start time, and lazy bean creation defers heavy services (AI runtime
  // client, MITM authority, scan tools) until first use. ~40s -> ~12s to
  // first ready on this machine; the first API request pays a small init
  // cost, but single-user desktop startup latency matters more than throughput.
      "-Dfile.encoding=UTF-8",
      "-Dsun.stdout.encoding=UTF-8",
      "-Dsun.stderr.encoding=UTF-8",
      "-XX:TieredStopAtLevel=1",
      "-jar",
      jar,
      "--spring.main.lazy-initialization=true",
      "--server.address=127.0.0.1",
      `--server.port=${port}`,
      `--spring.datasource.url=jdbc:h2:file:${databasePath};MODE=PostgreSQL;AUTO_SERVER=TRUE`,
    ],
    {
      cwd: userDataDir,
      env: backendEnv,
      stdio: ["ignore", stdout, stderr],
      windowsHide: true,
    },
  );
  backendProcess = child;
  fs.closeSync(stdout);
  fs.closeSync(stderr);
  child.once("exit", (code) => {
    if (backendProcess === child) backendProcess = undefined;
    if (
      !quitting &&
      !restartingBackend &&
      mainWindow &&
      !mainWindow.isDestroyed()
    ) {
      mainWindow.webContents.send("backend-exited", code);
    }
  });
  child.once("error", (error) => {
    backendStartError = new Error(`无法启动本地 Java 服务：${error.message}`);
  });
}

function isProcessAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // ESRCH: no such process. EPERM: exists but not signalable -> treat as alive.
    return error && error.code === "EPERM";
  }
}

function waitForProcessExit(pid, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  const waitBuffer = new Int32Array(new SharedArrayBuffer(4));
  while (isProcessAlive(pid) && Date.now() < deadline) {
    Atomics.wait(waitBuffer, 0, 0, 50);
  }
  return !isProcessAlive(pid);
}

function terminateWindowsProcessTree(pid, description) {
  let attempts = 0;
  let lastResult;
  let alive = true;
  do {
    attempts += 1;
    lastResult = spawnSync("taskkill.exe", ["/PID", String(pid), "/T", "/F"], {
      encoding: "utf8",
      windowsHide: true,
    });
    alive = !waitForProcessExit(pid);
  } while (alive && attempts < 2);
  const taskkillOutput = `${lastResult?.stdout || ""}${lastResult?.stderr || ""}`
    .replace(/[\r\n]+/g, " ")
    .trim()
    .slice(0, 1000);
  const context = {
    pid,
    description,
    attempts,
    alive,
    taskkillStatus: lastResult?.status ?? null,
    taskkillError: lastResult?.error?.message || null,
    taskkillOutput,
  };
  writeDesktopStartupDiagnostic(
    "process-stop",
    alive ? new Error(`${description} remains alive after taskkill`) : "process stopped",
    context,
  );
  if (alive) {
    console.error(`${description} (PID ${pid}) remains alive after taskkill`, context);
  }
  return !alive;
}

function cleanupStaleH2Lock(dataDir) {
  // The bundled JVM runs headless, so on Windows it can only be terminated
  // forcefully. H2 is crash-safe (MVStore + AUTO_SERVER), but a forced stop
  // leaves a stale `.lock.db` behind; on the next start H2 stalls on the lock
  // handshake, which makes first-connection noticeably slower. Remove it now
  // that no backend process we manage is running.
  if (process.platform !== "win32") return;
  try {
    const lockPath = path.join(dataDir, "security-toolbox.lock.db");
    if (fs.existsSync(lockPath) && !backendProcess) {
      fs.rmSync(lockPath, { force: true });
    }
  } catch (error) {
    writeDesktopStartupDiagnostic(
      "h2-lock-cleanup",
      new Error(`无法清理残留的 H2 锁文件：${error.message}`),
      { dataDir },
    );
  }
}

function requestGracefulBackendShutdown(port, token) {
  return new Promise((resolve) => {
    const body = Buffer.from("");
    const request = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path: "/api/system/shutdown",
        method: "POST",
        headers: {
          "Content-Length": 0,
          "X-Shutdown-Token": token || "",
        },
      },
      (response) => {
        response.resume();
        response.on("end", () => resolve({ ok: response.statusCode === 200 }));
      },
    );
    request.setTimeout(3000, () => request.destroy());
    request.on("error", () => resolve({ ok: false }));
    request.end(body);
  });
}

async function stopBackend() {
  if (!backendProcess || backendProcess.exitCode !== null) {
    backendProcess = undefined;
    return;
  }
  const pid = backendProcess.pid;
  const port = backendPort;
  const token = shutdownToken;
  backendProcess = undefined;
  if (process.platform !== "win32") {
    // On POSIX the JVM receives a real SIGTERM and runs its shutdown hooks.
    process.kill(pid, "SIGTERM");
  } else if (port && token) {
    // Ask the backend to exit cleanly so Spring's shutdown hooks close the H2
    // connection and release the lock. If it does not respond or exit quickly,
    // fall back to the forced tree kill below. A missing/mismatched endpoint
    // (e.g. an older JAR) is treated as not-graceful and still force-killed.
    const result = await requestGracefulBackendShutdown(port, token);
    if (result.ok && waitForProcessExit(pid, 5000)) {
      cleanupStaleH2Lock(path.join(app.getPath("userData"), "data"));
      return;
    }
    terminateWindowsProcessTree(pid, "Java backend");
  } else {
    // No endpoint/token available on Windows: only a forced kill is possible.
    terminateWindowsProcessTree(pid, "Java backend");
  }
  cleanupStaleH2Lock(path.join(app.getPath("userData"), "data"));
}

async function restartBackend() {
  if (!backendPort) return;
  restartingBackend = true;
  try {
    await stopBackend();
    startBackend(resolveJava(), resolveServerJar(), backendPort);
    await waitForBackend(backendPort);
  } finally {
    restartingBackend = false;
  }
}

async function restartAiRuntimeAndBackend() {
  stopAiRuntime();
  try {
    await startAiRuntime();
  } catch (error) {
    writeAiRuntimeDiagnostic(error);
    stopAiRuntime();
  }
  await restartBackend();
}

async function changeToolsDirectory(directory) {
  const selected = path.resolve(directory);
  ensureWritableDirectory(selected);
  const previousSettings = readDesktopSettings();
  const previousDirectory = resolveToolsDirectory();
  if (
    path.normalize(previousDirectory).toLowerCase() ===
    path.normalize(selected).toLowerCase()
  ) {
    return { changed: false, path: selected, toolsDirectory: selected };
  }
  writeDesktopSettings({ ...previousSettings, toolsDirectory: selected });
  try {
    await restartBackend();
    return { changed: true, path: selected, toolsDirectory: selected };
  } catch (error) {
    writeDesktopSettings({
      ...previousSettings,
      toolsDirectory: previousDirectory,
    });
    await restartBackend().catch(() => {});
    throw error;
  }
}

function createStartupWindow() {
  const startupTheme = currentSystemTheme();
  startupWindow = new BrowserWindow({
    width: 900,
    height: 620,
    icon: path.join(__dirname, "icon.png"),
    resizable: false,
    maximizable: false,
    show: false,
    backgroundColor: windowBackgroundColor(startupTheme),
    backgroundMaterial:
      startupTheme.transparencyEnabled && !startupTheme.highContrast
        ? startupTheme.windowMaterial
        : "none",
    autoHideMenuBar: true,
    webPreferences: {
      devTools: !app.isPackaged,
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
  });
  const startupEntry = path.join(__dirname, "startup.html");
  const guardStartupNavigation = (event, url) => {
    if (!isTrustedLocalFileUrl(url, startupEntry)) event.preventDefault();
  };
  startupWindow.webContents.on("will-navigate", guardStartupNavigation);
  startupWindow.webContents.on("will-redirect", guardStartupNavigation);
  startupWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  startupWindow.loadFile(startupEntry);
  startupWindow.once("ready-to-show", () => {
    applySystemThemeToStaticWindow(startupWindow);
    startupWindow.show();
  });
}

function createMainWindow(port) {
  const initialTheme = currentSystemTheme();
  mainWindow = new BrowserWindow({
    title: "獬豸授权安全测试平台",
    icon: path.join(__dirname, "icon.png"),
    width: 1380,
    height: 860,
    minWidth: 1000,
    minHeight: 700,
    show: false,
    backgroundColor: windowBackgroundColor(initialTheme),
    backgroundMaterial:
      initialTheme.transparencyEnabled && !initialTheme.highContrast
        ? initialTheme.windowMaterial
        : "none",
    autoHideMenuBar: true,
    webPreferences: {
      devTools: !app.isPackaged,
      preload: path.join(__dirname, "preload.cjs"),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      partition: "persist:security-toolbox-desktop-v2",
      additionalArguments: [`--backend-url=http://127.0.0.1:${port}/api`],
    },
  });
  const publishMaximizedState = () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(
        "toolbox:window-maximized-changed",
        mainWindow.isMaximized(),
      );
    }
  };
  mainWindow.on("maximize", publishMaximizedState);
  mainWindow.on("unmaximize", publishMaximizedState);
  const guardMainNavigation = (event, url) => {
    if (isTrustedMainRendererUrl(url)) return;
    event.preventDefault();
    if (String(url).startsWith("https://")) void shell.openExternal(url);
  };
  mainWindow.webContents.on("will-navigate", guardMainNavigation);
  mainWindow.webContents.on("will-redirect", guardMainNavigation);
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://")) shell.openExternal(url);
    return { action: "deny" };
  });
  mainWindow.webContents.on(
    "did-fail-load",
    (_event, errorCode, errorDescription, validatedURL) => {
      if (errorCode === -3) return;
      writeDesktopStartupDiagnostic("renderer-load", errorDescription, {
        errorCode,
        validatedURL: String(validatedURL || "").slice(0, 2048),
      });
      if (startupWindow && !startupWindow.isDestroyed()) {
        updateStartup(
          "工作区加载失败",
          "前端页面或资源无法载入。",
          "工作区页面加载失败，请重新启动应用或查看桌面日志。",
        );
      }
    },
  );
  const devUrl = process.env.TOOLBOX_DEV_URL;
  const backendUrl = `http://127.0.0.1:${port}/api`;
  if (devUrl) {
    const rendererUrl = new URL(devUrl);
    rendererUrl.searchParams.set("desktop", "1");
    rendererUrl.searchParams.set("backend", backendUrl);
    rendererUrl.hash = "/setup?startup=1&redirect=%2F";
    mainWindow.loadURL(rendererUrl.toString());
  } else {
    mainWindow.loadFile(path.join(app.getAppPath(), "dist", "index.html"), {
      query: { desktop: "1", backend: backendUrl },
      hash: "/setup?startup=1&redirect=%2F",
    });
  }
  mainWindow.once("ready-to-show", async () => {
    const showTheme = currentSystemTheme();
    if (!mainWindow.webContents.isDestroyed()) {
      const surface = JSON.stringify(sharedChromeSurface(showTheme));
      await mainWindow.webContents
        .executeJavaScript(
          `document.documentElement.style.setProperty('--shared-chrome-surface', ${surface})`,
        )
        .catch(() => {});
    }
    mainWindow.show();
    if (startupWindow && !startupWindow.isDestroyed()) startupWindow.close();
  });
  mainWindow.on("closed", () => {
    mainWindow = undefined;
    closeCaptureBrowser();
  });
  // Keep the native title bar fully owned by DWM. Setting an overlay/caption
  // color here would take precedence over the user's Windows personalization.
}

async function boot() {
  desktopLoginCredentialsIssued = false;
  let mitmCaMigration;
  createStartupWindow();
  try {
    updateStartup("检查并启动运行环境", "正在检查本地运行环境和服务文件。");
    ensureDesktopCredentials();
    const java = resolveJava();
    const jar = resolveServerJar();

    // 待 AI 进程被 spawn 之后会立刻 import langchain/langgraph/llama_index 并占满
    // CPU，把 Spring Boot 冷启动从约 12 秒拖到约 24 秒。这里把后端当成启动期的唯一
    // 重负载：先预分配 AI 运行时的回环端口与令牌，让 JVM 启动时就能绑定运行时客户端
    // 配置；AI 进程延迟到主窗口打开之后再 spawn，让图在后台编译。后端的
    // AiAgentRuntimeClient 在运行时健康检查通过前会降级为静态训练，所以把 AI 启动
    // 推迟到窗口之后不会影响正确性。
    backendPort = await findFreePort();
    mitmCaMigration = prepareDesktopMitmCaMigration();
    const aiSlot = await allocateAiRuntimeSlot();
    startBackend(java, jar, backendPort, {
      url: `http://127.0.0.1:${aiSlot.port}`,
      port: aiSlot.port,
      token: aiSlot.token,
      signingSecret: aiSlot.signingSecret,
    });
    updateStartup("检查并启动运行环境", "本地服务正在初始化，请稍候…");
    await waitForBackend(backendPort);
    completeDesktopMitmCaMigration(mitmCaMigration);
    mitmCaMigration = undefined;
    updateStartup("检测工具依赖", "本地服务已就绪，正在打开依赖检测与安装页面。");
    createMainWindow(backendPort);
    // 主窗口打开后再启动 AI，使其绝不阻塞启动窗与后端冷启动；图在后台编译。
    setImmediate(() => {
      spawnAiRuntime(aiSlot)
        .then((spawned) => waitForAiRuntimeReady(spawned.port))
        .catch((error) => {
          writeAiRuntimeDiagnostic(error);
          stopAiRuntime();
        });
    });
    // 漏洞知识库保持显式同步语义：启动时不自动联网下载或导入模板。
  } catch (error) {
    stopAiRuntime();
    await stopBackend();
    let recoveryError;
    try {
      rollbackDesktopMitmCaMigration(mitmCaMigration);
    } catch (failure) {
      recoveryError = failure;
    }
    writeDesktopStartupDiagnostic("boot", error);
    if (recoveryError)
      writeDesktopStartupDiagnostic("mitm-ca-recovery", recoveryError);
    updateStartup(
      "启动失败",
      "无法进入工具工作区。",
      "本地服务启动失败，请检查 Java 17 运行环境并查看桌面日志。",
    );
  }
}

if (hasSingleInstanceLock)
  app.whenReady().then(() => {
    systemPreferences.on("accent-color-changed", handleSystemThemeChanged);
    systemPreferences.on("color-changed", handleSystemThemeChanged);
    nativeTheme.on("updated", handleSystemThemeChanged);
    return boot();
  });
app.on("second-instance", () => {
  const window = mainWindow || startupWindow;
  if (!window || window.isDestroyed()) return;
  if (window.isMinimized()) window.restore();
  window.focus();
});
app.on("before-quit", (event) => {
  quitting = true;
  for (const session of activeInstalls.values()) {
    if (
      session.state === "running" &&
      ["downloading-package", "downloading-templates"].includes(session.phase)
    ) {
      session.intent = "pause";
      session.controller?.abort();
    }
  }
  systemPreferences.off("accent-color-changed", handleSystemThemeChanged);
  systemPreferences.off("color-changed", handleSystemThemeChanged);
  nativeTheme.off("updated", handleSystemThemeChanged);
  closeCaptureBrowser();
  stopAiRuntime();
  event.preventDefault();
  stopBackend()
    .catch(() => {})
    .finally(() => {
      quitting = true;
      app.exit(0);
    });
});
app.on("window-all-closed", () => app.quit());
app.on("activate", () => {
  if (!mainWindow && !startupWindow) boot();
});
