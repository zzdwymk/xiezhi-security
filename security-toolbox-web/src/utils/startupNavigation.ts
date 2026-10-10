export const SETUP_COMPLETE_KEY = "security_toolbox_setup_complete_v2";

export function isEntryPage(path: string) {
  const pathname = path.split(/[?#]/, 1)[0]?.replace(/\/+$/, "").toLowerCase();
  return pathname === "/setup" || pathname === "/login";
}

/** Login and setup are intermediate steps; preserve only their final workspace destination. */
export function workspaceRedirect(value: unknown): string {
  let candidate = value;
  for (let depth = 0; depth < 8; depth += 1) {
    if (
      typeof candidate !== "string" ||
      !candidate.startsWith("/") ||
      candidate.startsWith("//") ||
      candidate.includes("\\")
    ) return "/";
    try {
      const url = new URL(candidate, "http://toolbox.local");
      if (url.origin !== "http://toolbox.local") return "/";
      if (!isEntryPage(url.pathname)) return `${url.pathname}${url.search}${url.hash}`;
      candidate = url.searchParams.get("redirect");
    } catch {
      return "/";
    }
  }
  return "/";
}
