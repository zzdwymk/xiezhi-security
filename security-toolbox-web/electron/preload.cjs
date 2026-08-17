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
    minimizeWindow: () => ipcRenderer.invoke("toolbox:window-minimize"),
    toggleMaximizeWindow: () =>
      ipcRenderer.invoke("toolbox:window-toggle-maximize"),
    isWindowMaximized: () => ipcRenderer.invoke("toolbox:window-is-maximized"),
    closeWindow: () => ipcRenderer.invoke("toolbox:window-close"),
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
    getAiSettings: () => ipcRenderer.invoke("toolbox:get-ai-settings"),
    getIcpSettings: () => ipcRenderer.invoke("toolbox:get-icp-settings"),
    getGithubTokenSettings: () =>
      ipcRenderer.invoke("toolbox:get-github-token-settings"),
    saveGithubTokenSettings: (payload) =>
      ipcRenderer.invoke("toolbox:save-github-token-settings", payload),
    getDesktopLoginCredentials: () =>
      ipcRenderer.invoke("toolbox:get-desktop-login-credentials"),
    loginWithWindowsHello: () =>
      ipcRenderer.invoke("toolbox:desktop-login-with-hello"),
    setDesktopAdminPassword: (password) =>
      ipcRenderer.invoke("toolbox:set-desktop-admin-password", password),
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
