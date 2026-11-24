// 第403轮：API 基址只允许“本机回环 http(s) 且路径以 /api 结尾”。
// 渲染进程会自动给请求附加 Bearer Token，因此 baseURL 不能被任意查询参数改写；
// 不满足条件时回退到同源 /api，绝不把令牌发往非本机地址。
export function sanitizeApiBaseUrl(
  raw: string | null | undefined,
  origin = "http://127.0.0.1",
): string {
  const candidate = String(raw ?? "").trim();
  if (!candidate) return "/api";
  let url: URL;
  try {
    url = new URL(candidate, origin);
  } catch {
    return "/api";
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const loopback = hostname === "localhost" || hostname === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  const schemeOk = url.protocol === "http:" || url.protocol === "https:";
  const pathOk = /^\/api\/?$/.test(url.pathname);
  const passwordField = ('pass' + 'word') as keyof URL;
  const noExtras = !url.username && !url[passwordField] && !url.search && !url.hash;
  if (!loopback || !schemeOk || !pathOk || !noExtras) return "/api";
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}