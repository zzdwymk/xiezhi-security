/// <reference types="vite/client" />

type WindowMaterial = "none" | "mica" | "acrylic";

interface ToolboxDesktopBridge {
  readonly isDesktop: true;
  readonly platform: string;
  readonly backendBaseUrl: string;
  readonly getSystemTheme?: () => Promise<SystemThemeState>;
  readonly getMicaEnabled?: () => Promise<boolean>;
  readonly setMicaEnabled?: (enabled: boolean) => Promise<boolean>;
  readonly getWindowMaterial?: () => Promise<WindowMaterial>;
  readonly setWindowMaterial?: (
    material: WindowMaterial,
  ) => Promise<WindowMaterial>;
  readonly minimizeWindow?: () => Promise<void>;
  readonly toggleMaximizeWindow?: () => Promise<boolean>;
  readonly isWindowMaximized?: () => Promise<boolean>;
  readonly closeWindow?: () => Promise<void>;
  readonly onWindowMaximizedChanged?: (
    callback: (maximized: boolean) => void,
  ) => () => void;
  readonly onSystemThemeChanged?: (
    callback: (theme: SystemThemeState) => void,
  ) => () => void;
  readonly getToolsDirectory: () => Promise<string>;
  readonly chooseToolsDirectory?: () => Promise<
    | string
    | {
        changed?: boolean;
        canceled?: boolean;
        toolsDirectory?: string;
        path?: string;
      }
    | null
  >;
  readonly resetToolsDirectory?: () => Promise<
    string | { changed?: boolean; toolsDirectory?: string; path?: string }
  >;
  readonly listInstallableDependencies: () => Promise<
    Array<{
      packageId: string;
      version: string;
      optional?: boolean;
      uninstallSupported?: boolean;
    }>
  >;
  readonly installDependency: (
    packageId: string,
    options?: { refreshCatalog?: boolean },
  ) => Promise<{
    packageId: string;
    version?: string;
    latestVersion?: string;
    path?: string;
    toolsDirectory?: string;
    sha256?: string;
    integritySource?: string;
    status?: "paused" | "canceled" | "up-to-date";
    updated?: boolean;
    catalogUpdated?: boolean;
  }>;
  readonly controlDependencyInstall?: (
    packageId: string,
    action: "pause" | "cancel",
  ) => Promise<{ packageId: string; status: "paused" | "canceled" }>;
  readonly uninstallDependency?: (
    packageId: string,
  ) => Promise<{
    packageId: string;
    version?: string;
    status: "uninstalled";
  }>;
  readonly getAiSettings?: () => Promise<AiSettingsStatus>;
  readonly getIcpSettings?: () => Promise<IcpSettingsStatus>;
  readonly getGithubTokenSettings?: () => Promise<GithubTokenSettingsStatus>;
  readonly saveGithubTokenSettings?: (
    payload: GithubTokenSettingsInput,
  ) => Promise<GithubTokenSettingsStatus>;
  readonly getDesktopLoginCredentials?: () => Promise<DesktopLoginCredentials | null>;
  readonly loginWithWindowsHello?: () => Promise<{
    verified: boolean;
    available?: boolean;
    reason?: string;
    credentials?: DesktopLoginCredentials | null;
  }>;
  readonly setDesktopAdminPassword?: (
    password: string,
  ) => Promise<{ updated: boolean }>;
  readonly testAiSettings?: (
    settings: AiSettingsInput,
  ) => Promise<{ ok: boolean; model: string; message: string }>;
  readonly testEmbeddingSettings?: (
    settings: AiSettingsInput,
  ) => Promise<{ ok: boolean; model: string; message: string }>;
  readonly saveAiSettings?: (
    settings: AiSettingsInput,
  ) => Promise<AiSettingsStatus>;
  readonly clearAiApiKey?: (
    settings: AiSettingsInput,
  ) => Promise<AiSettingsStatus>;
  readonly clearEmbeddingApiKey?: (
    settings: AiSettingsInput,
  ) => Promise<AiSettingsStatus>;
  readonly saveIcpSettings?: (
    settings: IcpSettingsInput,
  ) => Promise<IcpSettingsStatus>;
  readonly clearIcpSettings?: () => Promise<IcpSettingsStatus>;
  readonly getToolDownloadSettings?: () => Promise<ToolDownloadSettingsStatus>;
  readonly saveToolDownloadSettings?: (
    payload: ToolDownloadSettingsInput,
  ) => Promise<ToolDownloadSettingsStatus>;
  readonly launchCaptureBrowser?: (
    options: CaptureBrowserOptions,
  ) => Promise<CaptureBrowserStatus>;
  readonly closeCaptureBrowser?: () => Promise<CaptureBrowserStatus>;
  readonly getCaptureBrowserStatus?: () => Promise<CaptureBrowserStatus>;
  readonly setProgressBar?: (
    progress: number,
    options?: {
      mode?: "none" | "normal" | "indeterminate" | "error" | "paused";
    },
  ) => Promise<void>;
  readonly onCaptureBrowserClosed?: (callback: () => void) => () => void;
  readonly openIcpBrowser?: (
    payload: IcpBrowserOpenOptions,
  ) => Promise<IcpBrowserStatus>;
  readonly fetchIcpBrowserResult?: () => Promise<IcpBrowserCaptureResult>;
  readonly closeIcpBrowser?: () => Promise<IcpBrowserStatus>;
  readonly getIcpBrowserStatus?: () => Promise<IcpBrowserStatus>;
  readonly onIcpBrowserClosed?: (callback: () => void) => () => void;
  readonly onDependencyInstallProgress?: (
    callback: (event: DependencyInstallProgressEvent) => void,
  ) => () => void;
}

interface SystemThemeState {
  readonly accentColor: string;
  readonly captionColor: string;
  readonly captionMode: "accent" | "mica" | "solid";
  readonly useAccentOnTitleBars: boolean;
  readonly forcedCaptionAccent: boolean;
  readonly transparencyEnabled: boolean;
  readonly windowMaterial?: WindowMaterial;
  readonly autoColorization: boolean;
  readonly appsUseLightTheme: boolean;
  readonly systemUsesLightTheme: boolean;
  readonly dark: boolean;
  readonly highContrast: boolean;
}

interface CaptureBrowserOptions {
  proxyHost: string;
  proxyPort: number;
  targetUrl: string;
  caFingerprint?: string;
}

interface CaptureBrowserStatus {
  readonly running: boolean;
  readonly proxyHost?: string;
  readonly proxyPort?: number;
  readonly targetUrl?: string;
  readonly mitmTrusted?: boolean;
}

interface IcpBrowserOpenOptions {
  domain: string;
}

interface IcpBrowserStatus {
  readonly running: boolean;
  readonly opening?: boolean;
  readonly domain?: string;
  readonly url?: string;
  readonly lastError?: string;
  readonly lastFetch?: string;
}

interface IcpBrowserCaptureResult {
  ok: boolean;
  found?: number;
  rows?: Array<Record<string, unknown>>;
  /** Original MIIT query response packet ({code,msg,params:{list:[…]}}), when captured. */
  raw?: Record<string, unknown> | null;
  pageText?: string;
  reason?: string;
  error?: string;
}

interface AiSettingsInput {
  baseUrl: string;
  model: string;
  retrievalBackend: "bm25" | "real_embedding";
  embeddingModel: string;
  embeddingConnectionMode: "shared" | "custom";
  embeddingBaseUrl: string;
  embeddingApiKey?: string;
  apiKey?: string;
  proxyMode: boolean;
}

interface AiSettingsStatus {
  readonly baseUrl: string;
  readonly model: string;
  readonly retrievalBackend: "bm25" | "real_embedding";
  readonly embeddingModel: string;
  readonly embeddingConnectionMode: "shared" | "custom";
  readonly embeddingBaseUrl: string;
  readonly hasEmbeddingApiKey: boolean;
  readonly embeddingKeyHint: string;
  readonly hasApiKey: boolean;
  readonly proxyMode: boolean;
  readonly apiMode: "chat_completions" | "responses";
  readonly keyHint: string;
  readonly provider: "openai-compatible" | "local-rule-fallback";
  readonly encryptionAvailable: boolean;
}

interface IcpSettingsInput {
  apiUrl: string;
}

interface IcpSettingsStatus {
  readonly configured: boolean;
  readonly endpointHint: string;
  readonly source: "desktop" | "environment" | "none";
  readonly encryptionAvailable: boolean;
}

interface GithubTokenSettingsInput {
  token?: string;
  clear?: boolean;
}

interface GithubTokenSettingsStatus {
  readonly configured: boolean;
  readonly source: "env" | "settings" | "none";
  readonly encryptionAvailable: boolean;
  readonly hint: string;
}

interface ToolDownloadSettingsInput {
  readonly downloadMirror?: string;
}

interface ToolDownloadSettingsStatus {
  readonly configuredMirror: string;
}

interface DesktopLoginCredentials {
  readonly username: string;
  readonly password: string;
}

interface DependencyInstallProgressEvent {
  readonly packageId: string;
  readonly stage?: string;
  readonly installStage?: string;
  readonly progress?: number;
  readonly progressDeterminate?: boolean;
  readonly downloadedBytes?: number;
  readonly totalBytes?: number;
  readonly resumed?: boolean;
  readonly resumedBytes?: number;
  readonly processedFiles?: number;
  readonly totalFiles?: number;
  readonly rangeAccepted?: boolean;
  readonly installing?: boolean;
  readonly paused?: boolean;
  readonly canPause?: boolean;
  readonly elapsedSeconds?: number;
  readonly logs?: string[];
}

interface Window {
  readonly toolboxDesktop?: ToolboxDesktopBridge;
}
