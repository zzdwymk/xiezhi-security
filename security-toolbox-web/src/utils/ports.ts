export interface PortOption {
  label: string;
  value: string;
}

export const COMMON_PORT_OPTIONS: PortOption[] = [
  { label: "HTTP · 80", value: "80" },
  { label: "HTTPS · 443", value: "443" },
  { label: "SSH · 22", value: "22" },
  { label: "FTP · 21", value: "21" },
  { label: "SMTP · 25", value: "25" },
  { label: "DNS · 53", value: "53" },
  { label: "POP3 · 110", value: "110" },
  { label: "IMAP · 143", value: "143" },
  { label: "SMB · 445", value: "445" },
  { label: "MySQL · 3306", value: "3306" },
  { label: "RDP · 3389", value: "3389" },
  { label: "PostgreSQL · 5432", value: "5432" },
  { label: "Redis · 6379", value: "6379" },
  { label: "HTTP 备用 · 8080", value: "8080" },
  { label: "HTTPS 备用 · 8443", value: "8443" },
];

export function normalizeAllowedPorts(
  selectedPorts: string[] = [],
  customPorts: string = "",
  fullPortAccess: boolean = false,
): string {
  if (fullPortAccess) return "1-65535";
  const source = [
    ...selectedPorts,
    ...customPorts.split(/[，,;；、\s]+/),
  ].filter(Boolean);
  const normalized = new Set<string>();

  for (const raw of source) {
    const token = raw.trim().replace(/[—–~～]/g, "-");
    const match = token.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!match) throw new Error(`端口格式无效：${raw}`);
    const start = Number(match[1]);
    const end = match[2] ? Number(match[2]) : undefined;
    if (
      start < 1 ||
      start > 65535 ||
      (end !== undefined && (end < 1 || end > 65535 || end < start))
    ) {
      throw new Error(`端口范围无效：${raw}`);
    }
    normalized.add(end === undefined ? String(start) : `${start}-${end}`);
  }

  if (!normalized.size) throw new Error("请至少选择或填写一个允许端口");
  return [...normalized]
    .sort((a, b) => Number(a.split("-")[0]) - Number(b.split("-")[0]))
    .join(",");
}

export function validateDomainTarget(value: string, targetType: string): void {
  const type = (targetType || "").toLowerCase();
  const trimmed = (value || "").trim();
  if (!trimmed) {
    throw new Error("目标地址不能为空");
  }
  if (type === "domain") {
    const valid =
      /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,}$/i.test(
        trimmed,
      );
    if (!valid) {
      throw new Error("域名格式不正确：请填写不含空格、协议或路径的主机名");
    }
  } else if (type === "ip") {
    const ipv4 =
      /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    if (!ipv4.test(trimmed)) {
      throw new Error(
        "IP 地址格式不正确：请填写标准的 IPv4 地址（如 192.168.1.1），不得包含协议、路径或末尾多余符号",
      );
    }
  } else if (type === "url") {
    if (!/^https?:\/\/[a-zA-Z0-9.-]+(?::\d{1,5})?(?:\/\S*)?$/i.test(trimmed)) {
      throw new Error("URL 格式不正确：请填写以 http:// 或 https:// 开头的合法 URL 地址");
    }
  }
}

export function inferTargetType(value: string): "ip" | "url" | "domain" | null {
  const trimmed = (value || "").trim();
  if (!trimmed) return null;
  if (/^https?:\/\//i.test(trimmed)) {
    return "url";
  }
  const ipv4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  if (ipv4.test(trimmed)) {
    return "ip";
  }
  // 带端口的 IPv4 地址（如 192.168.1.1:8080），归入 URL 类型
  if (/^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}:\d{1,5}$/.test(trimmed)) {
    return "url";
  }
  // IPv6 地址（如 ::1 或 [::1]:80）
  if (/^\[?[0-9a-fA-F:]+\]?(?::\d{1,5})?$/.test(trimmed) && trimmed.includes(":") && !trimmed.startsWith("http")) {
    return "ip";
  }
  const domain =
    /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,}(?::\d{1,5})?$/i;
  if (domain.test(trimmed) && trimmed.includes(".")) {
    return trimmed.includes(":") ? "url" : "domain";
  }
  if (/^localhost(?::\d{1,5})?$/i.test(trimmed)) {
    return trimmed.includes(":") ? "url" : "domain";
  }
  return null;
}
