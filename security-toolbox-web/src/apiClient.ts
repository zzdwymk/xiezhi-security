import axios from "axios";
import { clearAuthToken, notifyAuthExpired, readAuthToken } from "./authToken";

const query = new URLSearchParams(window.location.search);
const desktopMode = Boolean(
  window.toolboxDesktop?.isDesktop || query.get("desktop") === "1",
);
const apiBaseUrl =
  query.get("backend") || window.toolboxDesktop?.backendBaseUrl || "/api";

export const api = axios.create({
  baseURL: apiBaseUrl,
  timeout: 10_000,
});

api.interceptors.request.use((config) => {
  const token = readAuthToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) redirectToLogin();
    return Promise.reject(error);
  },
);

export function apiUrl(path: string): string {
  const base = apiBaseUrl.endsWith("/") ? apiBaseUrl.slice(0, -1) : apiBaseUrl;
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return new URL(`${base}${suffix}`, window.location.origin).toString();
}

function redirectToLogin() {
  clearAuthToken();
  notifyAuthExpired();

  const current = desktopMode
    ? location.hash.replace(/^#/, "") || "/"
    : location.pathname;
  if (current.startsWith("/login")) return;

  const login = `/login?redirect=${encodeURIComponent(current)}`;
  if (desktopMode) location.hash = `#${login}`;
  else location.assign(login);
}
