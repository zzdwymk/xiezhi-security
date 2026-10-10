/** Treat payload text literally and replace every occurrence of the named marker. */
export function replaceFuzzNameMarker(template: string, payload: string): string {
  return template.split("\u00a7name\u00a7").join(payload);
}

/** Match the visible dictionary's nonblank lines without deduplicating or mutating its draft. */
export function normalizeFuzzDictionary(text: unknown): string[] {
  return typeof text === "string" ? text.split(/\r?\n/).map(line => line.trim()).filter(Boolean) : [];
}

/** Multi-dictionary modes require an explicit nonblank payload for every participating variable. */
export function validateFuzzDictionaries(
  variables: readonly string[],
  groups: Readonly<Record<string, unknown>>,
): string | undefined {
  const missing = variables.filter(name => {
    if (!Object.prototype.hasOwnProperty.call(groups, name)) return true;
    const values = groups[name];
    return !Array.isArray(values) || !values.some(value => typeof value === "string" && value.trim().length > 0);
  });
  return missing.length
    ? `多字典模式的每个占位符都需要至少一行非空载荷：${missing.map(name => `§${name}§`).join("、")}`
    : undefined;
}

export interface FuzzReplayRequest {
  method: string;
  url: string;
  headers: string;
  body: string;
}

export const FUZZ_REPLAY_UNAVAILABLE =
  "该结果未保存完整有效的请求，无法准确重放。请重新运行循环模糊测试后重试。";

/** Only the captured request is replayable: payload labels may be truncated or summarize several values. */
export function readFuzzReplayRequest(value: unknown): FuzzReplayRequest | undefined {
  if (!value || typeof value !== "object") return undefined;
  const request = value as Record<string, unknown>;
  if (
    typeof request.method !== "string" ||
    !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(request.method) ||
    typeof request.url !== "string" ||
    /[\u0000-\u0020\u007f]/.test(request.url) ||
    typeof request.headers !== "string" ||
    typeof request.body !== "string"
  ) return undefined;
  try {
    const url = new URL(request.url);
    if (!/^https?:$/.test(url.protocol) || !url.hostname) return undefined;
  } catch {
    return undefined;
  }
  // Copy the four strings verbatim; later draft edits must not mutate the saved result.
  return { method: request.method, url: request.url, headers: request.headers, body: request.body };
}

/** Reconcile the two visible address editors using the user's most recent edit. */
export function resolveFuzzAddress(
  url: string,
  raw: string,
  edited: "url" | "raw",
): { url: string; raw: string } {
  const line = /^([^\s]+)([ \t]+)([^\s]+)([^\r\n]*)/.exec(raw);
  if (!line) return { url, raw };
  if (edited === "url") {
    // Keep the exact marker/Unicode spelling and the complete header/body bytes.
    // URL.href would percent-encode markers before the payload generator sees them.
    const targetStart = line[1].length + line[2].length;
    return { url, raw: raw.slice(0, targetStart) + url.trim() + raw.slice(targetStart + line[3].length) };
  }
  const target = line[3];
  if (/^https?:\/\//i.test(target)) return { url: target, raw };
  const origin = /^(https?:\/\/[^/?#]+)/i.exec(url.trim())?.[1];
  if (target.startsWith("/") && origin) return { url: origin + target, raw };
  // Preserve the existing handling of other request-target forms; backend validation
  // still decides whether the final request can be sent.
  return { url, raw };
}
