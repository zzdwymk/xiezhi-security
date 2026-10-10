import axios from "axios";
import { clearAuthToken, notifyAuthExpired, readAuthToken } from "./authToken";
import { taskbarProgress } from "./utils/taskbarProgress";
import { isEntryPage, workspaceRedirect } from "./utils/startupNavigation";

let requestIdCounter = 0;

const query = new URLSearchParams(window.location.search);
const desktopMode = Boolean(
  window.toolboxDesktop?.isDesktop || query.get("desktop") === "1",
);
export const apiBaseUrl =
  query.get("backend") || window.toolboxDesktop?.backendBaseUrl || "/api";

export function getApiUrl(path: string): string {
  const normalized = apiBaseUrl.replace(/\/+$/, "");
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${normalized}${normalizedPath}`;
}

export const api = axios.create({
  baseURL: apiBaseUrl,
  timeout: 10_000,
});

api.interceptors.request.use((config) => {
  const token = readAuthToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;

  const method = String(config.method || "get").toLowerCase();
  const isMutating = ["post", "put", "delete", "patch"].includes(method);
  const isExplicit = (config as { taskbar?: boolean }).taskbar === true;
  const isSilent =
    (config as { silent?: boolean }).silent === true ||
    Boolean(config.url && config.url.includes("/system/health"));

  if (!isSilent && (isMutating || isExplicit)) {
    const reqId = `http-req-${++requestIdCounter}`;
    (config as unknown as Record<string, unknown>).__reqId = reqId;
    taskbarProgress.startIndeterminate(reqId);
  }

  return config;
});

api.interceptors.response.use(
  (response) => {
    const reqId = (response.config as unknown as Record<string, unknown>)?.__reqId;
    if (typeof reqId === "string") taskbarProgress.stopIndeterminate(reqId);
    return response;
  },
  (error) => {
    const reqId = (error?.config as unknown as Record<string, unknown>)?.__reqId;
    if (typeof reqId === "string") taskbarProgress.stopIndeterminate(reqId);
    if (error?.response?.status === 401)
      redirectToLogin(requestAuthToken(error?.config?.headers));
    return Promise.reject(error);
  },
);

export function apiUrl(path: string): string {
  const base = apiBaseUrl.endsWith("/") ? apiBaseUrl.slice(0, -1) : apiBaseUrl;
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return new URL(`${base}${suffix}`, window.location.origin).toString();
}

/** Give fetch-based event streams the same expired-session handling as Axios. */
export async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const requestHeaders = new Headers(
    init?.headers ?? (typeof Request !== "undefined" && input instanceof Request ? input.headers : undefined),
  );
  const requestToken = requestAuthToken(requestHeaders);
  const response = await fetch(input, init);
  if (response.status === 401) {
    redirectToLogin(requestToken);
    throw new Error("登录已失效，请重新登录后继续操作");
  }
  return response;
}

function requestAuthToken(headers: { get?: (name: string) => unknown; Authorization?: unknown; authorization?: unknown } | undefined) {
  const authorization = headers?.get?.("Authorization") ?? headers?.Authorization ?? headers?.authorization;
  return typeof authorization === "string" ? /^Bearer\s+(.+)$/i.exec(authorization)?.[1] || "" : "";
}

function redirectToLogin(requestToken: string) {
  // Anonymous requests and late responses from a previous login must not expire the current session.
  if (!requestToken || requestToken !== readAuthToken()) return;
  clearAuthToken();
  notifyAuthExpired();

  const current = desktopMode
    ? location.hash.replace(/^#/, "") || "/"
    : `${location.pathname}${location.search || ""}${location.hash || ""}`;
  if (isEntryPage(current)) return;

  const login = `/login?redirect=${encodeURIComponent(workspaceRedirect(current))}`;
  if (desktopMode) location.hash = `#${login}`;
  else location.assign(login);
}
