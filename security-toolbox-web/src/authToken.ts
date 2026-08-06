const PERSISTENT_TOKEN_KEY = "security_toolbox_token";
const SESSION_TOKEN_KEY = "security_toolbox_session_token";
export const AUTH_EXPIRED_EVENT = "security-toolbox-auth-expired";

export function readAuthToken() {
  return (
    localStorage.getItem(PERSISTENT_TOKEN_KEY) ||
    sessionStorage.getItem(SESSION_TOKEN_KEY) ||
    ""
  );
}

export function storeAuthToken(token: string, persistent: boolean) {
  clearAuthToken();
  if (persistent) localStorage.setItem(PERSISTENT_TOKEN_KEY, token);
  else sessionStorage.setItem(SESSION_TOKEN_KEY, token);
}

export function clearAuthToken() {
  localStorage.removeItem(PERSISTENT_TOKEN_KEY);
  sessionStorage.removeItem(SESSION_TOKEN_KEY);
}

export function notifyAuthExpired() {
  window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
}

export function hasPersistentAuthToken() {
  return Boolean(localStorage.getItem(PERSISTENT_TOKEN_KEY));
}
