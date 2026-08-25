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
  if (targetType.toLowerCase() !== "domain") return;
  const domain = value.trim();
  const valid =
    /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)*[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(
      domain,
    );
  if (!valid) {
    throw new Error("域名格式不正确：请填写不含空格、协议或路径的主机名");
  }
}
