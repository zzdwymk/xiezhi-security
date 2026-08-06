interface ErrorLike {
  code?: string;
  message?: string;
  response?: {
    status?: number;
    data?: { message?: string } | string;
  };
}

const REMOTE_METHOD_PREFIX =
  /^Error invoking remote method '[^']+':\s*(?:Error:\s*)?/i;

function responseMessage(error: ErrorLike) {
  const data = error.response?.data;
  return typeof data === "string" ? data : data?.message;
}

export function toErrorMessage(error: unknown, fallback: string): string {
  const value = (error && typeof error === "object" ? error : {}) as ErrorLike;
  const directMessage = typeof error === "string" ? error : "";
  const raw = String(responseMessage(value) || value.message || directMessage)
    .replace(REMOTE_METHOD_PREFIX, "")
    .trim();
  const status = value.response?.status;

  if (value.code === "ECONNABORTED" || /\btimeout\b/i.test(raw)) {
    return `${fallback}：请求超时，请稍后重试`;
  }
  if (
    value.code === "ERR_NETWORK" ||
    /network error|failed to fetch|fetch failed|connection refused|econnrefused|err_connection_refused/i.test(
      raw,
    )
  ) {
    return `${fallback}：无法连接本地服务`;
  }
  if (/^request failed with status code \d+$/i.test(raw)) {
    return `${fallback}：请求失败（HTTP ${status || raw.match(/\d+/)?.[0]}）`;
  }
  const containsInternalDetail =
    /(?:exception|traceback|stack trace|\bat\s+\S+\([^)]*:\d+\)|[a-z]:\\|\/(?:home|users|usr|var|opt)\/)/i.test(
      raw,
    );
  if (/[\u3400-\u9fff]/.test(raw) && !containsInternalDetail) return raw;
  if (status) return `${fallback}（HTTP ${status}）`;
  return fallback;
}
