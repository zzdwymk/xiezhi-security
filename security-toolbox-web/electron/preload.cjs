const { contextBridge, ipcRenderer } = require("electron");

const backendArg = process.argv.find((value) =>
  value.startsWith("--backend-url="),
);
const backendBaseUrl = backendArg
  ? backendArg.substring("--backend-url=".length)
  : "http://127.0.0.1:18080/api";

contextBridge.exposeInMainWorld(
  "toolboxDesktop",
  Object.freeze({
    isDesktop: true,
    platform: process.platform,
    backendBaseUrl,
    getSystemTheme: () => ipcRenderer.invoke("toolbox:get-system-theme"),
    getMicaEnabled: () => ipcRenderer.invoke("toolbox:get-mica-enabled"),
    setMicaEnabled: (enabled) =>
      ipcRenderer.invoke("toolbox:set-mica-enabled", enabled),
    getWindowMaterial: () => ipcRenderer.invoke("toolbox:get-window-material"),
    setWindowMaterial: (material) =>
      ipcRenderer.invoke("toolbox:set-window-material", material),
    getThemeMode: () => ipcRenderer.invoke("toolbox:get-theme-mode"),
    setThemeMode: (mode) => ipcRenderer.invoke("toolbox:set-theme-mode", mode),
    getMotionSettings: () => ipcRenderer.invoke("toolbox:get-motion-settings"),
    setMotionSettings: (flags) =>
      ipcRenderer.invoke("toolbox:set-motion-settings", flags),
    minimizeWindow: () => ipcRenderer.invoke("toolbox:window-minimize"),
    toggleMaximizeWindow: () =>
      ipcRenderer.invoke("toolbox:window-toggle-maximize"),
    isWindowMaximized: () => ipcRenderer.invoke("toolbox:window-is-maximized"),
    closeWindow: () => ipcRenderer.invoke("toolbox:window-close"),
    openExternal: (url) => ipcRenderer.invoke("toolbox:open-external", url),
    onWindowMaximizedChanged: (callback) => {
      const listener = (_event, maximized) => callback(Boolean(maximized));
      ipcRenderer.on("toolbox:window-maximized-changed", listener);
      return () =>
        ipcRenderer.removeListener(
          "toolbox:window-maximized-changed",
          listener,
        );
    },
    onSystemThemeChanged: (callback) => {
      const listener = (_event, theme) => callback(theme);
      ipcRenderer.on("toolbox:system-theme-changed", listener);
      return () =>
        ipcRenderer.removeListener("toolbox:system-theme-changed", listener);
    },
    getToolsDirectory: () => ipcRenderer.invoke("toolbox:get-tools-directory"),
    chooseToolsDirectory: () =>
      ipcRenderer.invoke("toolbox:choose-tools-directory"),
    resetToolsDirectory: () =>
      ipcRenderer.invoke("toolbox:reset-tools-directory"),
    listInstallableDependencies: () =>
      ipcRenderer.invoke("toolbox:list-installable-dependencies"),
    installDependency: (packageId, options) =>
      ipcRenderer.invoke("toolbox:install-dependency", packageId, {
        refreshCatalog: options?.refreshCatalog === true,
      }),
    controlDependencyInstall: (packageId, action) =>
      ipcRenderer.invoke("toolbox:control-dependency-install", {
        packageId,
        action,
      }),
    uninstallDependency: (packageId) =>
      ipcRenderer.invoke("toolbox:uninstall-dependency", packageId),
    getPostgresMigrationState: () =>
      ipcRenderer.invoke("toolbox:get-postgres-migration-state"),
    migrateToPostgres: (options) =>
      ipcRenderer.invoke("toolbox:migrate-to-postgres", {
        copyH2: options?.copyH2 === true,
      }),
    rollbackFromPostgres: () =>
      ipcRenderer.invoke("toolbox:rollback-from-postgres"),
    setPostgresPassword: (password) =>
      ipcRenderer.invoke("toolbox:set-postgres-password", { password }),
    onPostgresMigrationProgress: (callback) => {
      const listener = (_event, progress) => callback(progress);
      ipcRenderer.on("toolbox:postgres-migration-progress", listener);
      return () =>
        ipcRenderer.removeListener(
          "toolbox:postgres-migration-progress",
          listener,
        );
    },
    getAiSettings: () => ipcRenderer.invoke("toolbox:get-ai-settings"),
    getIcpSettings: () => ipcRenderer.invoke("toolbox:get-icp-settings"),
    getToolDownloadSettings: () =>
      ipcRenderer.invoke("toolbox:get-tool-download-settings"),
    saveToolDownloadSettings: (payload) =>
      ipcRenderer.invoke("toolbox:save-tool-download-settings", payload),
    getGithubTokenSettings: () =>
      ipcRenderer.invoke("toolbox:get-github-token-settings"),
    saveGithubTokenSettings: (payload) =>
      ipcRenderer.invoke("toolbox:save-github-token-settings", payload),
    getDesktopLoginCredentials: () =>
      ipcRenderer.invoke("toolbox:get-desktop-login-credentials"),
    getDesktopLoginBinding: () =>
      ipcRenderer.invoke("toolbox:get-desktop-login-binding"),
    bindDesktopLogin: () =>
      ipcRenderer.invoke("toolbox:bind-desktop-login"),
    unbindDesktopLogin: () =>
      ipcRenderer.invoke("toolbox:unbind-desktop-login"),
    loginWithWindowsHello: () =>
      ipcRenderer.invoke("toolbox:desktop-login-with-hello"),
    setDesktopAdminPassword: (password) =>
      ipcRenderer.invoke("toolbox:set-desktop-admin-password", password),
    changeDesktopAdminPassword: (password) =>
      ipcRenderer.invoke("toolbox:change-desktop-admin-password", { password }),
    generateDesktopLogin: () =>
      ipcRenderer.invoke("toolbox:generate-desktop-login"),
    initDesktopLogin: (password) =>
      ipcRenderer.invoke("toolbox:init-desktop-login", { password }),
    reimportH2ToPostgres: () =>
      ipcRenderer.invoke("toolbox:reimport-h2-to-postgres"),
    testAiSettings: (settings) =>
      ipcRenderer.invoke("toolbox:test-ai-settings", settings),
    testEmbeddingSettings: (settings) =>
      ipcRenderer.invoke("toolbox:test-embedding-settings", settings),
    saveAiSettings: (settings) =>
      ipcRenderer.invoke("toolbox:save-ai-settings", settings),
    clearAiApiKey: (settings) =>
      ipcRenderer.invoke("toolbox:clear-ai-api-key", settings),
    clearEmbeddingApiKey: (settings) =>
      ipcRenderer.invoke("toolbox:clear-embedding-api-key", settings),
    saveIcpSettings: (settings) =>
      ipcRenderer.invoke("toolbox:save-icp-settings", settings),
    clearIcpSettings: () => ipcRenderer.invoke("toolbox:clear-icp-settings"),
    launchCaptureBrowser: (options) =>
      ipcRenderer.invoke("toolbox:launch-capture-browser", options),
    closeCaptureBrowser: () =>
      ipcRenderer.invoke("toolbox:close-capture-browser"),
    getCaptureBrowserStatus: () =>
      ipcRenderer.invoke("toolbox:get-capture-browser-status"),
    onCaptureBrowserClosed: (callback) => {
      const listener = () => callback();
      ipcRenderer.on("toolbox:capture-browser-closed", listener);
      return () =>
        ipcRenderer.removeListener("toolbox:capture-browser-closed", listener);
    },
    openIcpBrowser: (payload) =>
      ipcRenderer.invoke("toolbox:open-icp-browser", payload),
    fetchIcpBrowserResult: () =>
      ipcRenderer.invoke("toolbox:fetch-icp-browser-result"),
    closeIcpBrowser: () => ipcRenderer.invoke("toolbox:close-icp-browser"),
    getIcpBrowserStatus: () =>
      ipcRenderer.invoke("toolbox:get-icp-browser-status"),
    onIcpBrowserClosed: (callback) => {
      const listener = () => callback();
      ipcRenderer.on("toolbox:icp-browser-closed", listener);
      return () =>
        ipcRenderer.removeListener("toolbox:icp-browser-closed", listener);
    },
    setProgressBar: (progress, options) =>
      ipcRenderer.invoke("toolbox:set-progress-bar", progress, options),
    showTaskNotification: (payload) =>
      ipcRenderer.invoke("toolbox:show-task-notification", payload),
    getNotificationSettings: () =>
      ipcRenderer.invoke("toolbox:get-notification-settings"),
    saveNotificationSettings: (payload) =>
      ipcRenderer.invoke("toolbox:set-notification-settings", payload),
    onDependencyInstallProgress: (callback) => {
      const listener = (_event, progress) => callback(progress);
      ipcRenderer.on("toolbox:dependency-install-progress", listener);
      return () =>
        ipcRenderer.removeListener(
          "toolbox:dependency-install-progress",
          listener,
        );
    },
  }),
);

// 消除深色模式刷新闪白：在 DOM 刚生成时第一时间应用深色模式，绝不出现未样式化白色闪烁
try {
  const initEarlyTheme = () => {
    const root = document.documentElement;
    if (!root) return;
    const mode = localStorage.getItem("security_toolbox_theme_mode_v1") || "system";
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const isDark = mode === "dark" || (mode === "system" && prefersDark);
    root.dataset.systemTheme = isDark ? "dark" : "light";
    root.style.colorScheme = isDark ? "dark" : "light";
    if (isDark) {
      root.classList.add("dark");
      root.style.backgroundColor = "#121216";
      if (document.body) document.body.style.backgroundColor = "#121216";
    }
  };
  initEarlyTheme();
  window.addEventListener("DOMContentLoaded", initEarlyTheme, { once: true });
} catch {
  // ignore
}
