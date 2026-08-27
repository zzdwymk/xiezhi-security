export interface ParsedTargetItem {
  id?: string;
  name: string;
  targetValue: string;
  targetType: "ip" | "domain" | "url";
  customPorts?: string;
  isFullPort?: boolean;
}

export interface ParseBatchResult {
  items: ParsedTargetItem[];
  stats: {
    total: number;
    ipCount: number;
    domainCount: number;
    urlCount: number;
    customPortCount: number;
  };
  errors: string[];
}

const DOMAIN_REGEX =
  /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
const IPV4_REGEX =
  /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const CIDR_REGEX =
  /^((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\/(\d{1,2})$/;
const IP_RANGE_FULL_REGEX =
  /^((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})-((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IP_RANGE_SHORT_REGEX =
  /^((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}\.)(\d{1,3})-(\d{1,3})$/;

function ipToNumber(ip: string): number {
  return ip
    .split(".")
    .reduce((acc, octet) => ((acc << 8) + Number(octet)) >>> 0, 0);
}

function numberToIp(num: number): string {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255,
  ].join(".");
}

/**
 * Extracts optional port suffix from a raw line.
 * Examples:
 *   "192.168.1.10:80,443"       -> target: "192.168.1.10", ports: "80,443", isFull: false
 *   "192.168.1.10:all"          -> target: "192.168.1.10", ports: "1-65535", isFull: true
 *   "192.168.1.0/28 [80,443]"   -> target: "192.168.1.0/28", ports: "80,443", isFull: false
 *   "example.com:22,80-90"      -> target: "example.com", ports: "22,80-90", isFull: false
 */
function extractPortSpec(line: string): {
  cleanTarget: string;
  customPorts?: string;
  isFullPort?: boolean;
} {
  // If it's a URL, don't split by colon arbitrarily
  if (/^https?:\/\//i.test(line)) {
    try {
      const url = new URL(line);
      const explicitPort = url.port || (url.protocol === "https:" ? "443" : "80");
      return {
        cleanTarget: line,
        customPorts: explicitPort,
        isFullPort: false,
      };
    } catch {
      return { cleanTarget: line };
    }
  }

  // Check bracket notation: target [80,443] or target (80,443)
  const bracketMatch = line.match(/^(.+?)\s*[\[\(]([0-9,\s\-—–~～]+|all|full)[\]\)]$/i);
  if (bracketMatch) {
    const targetPart = bracketMatch[1].trim();
    const portRaw = bracketMatch[2].trim().toLowerCase();
    if (portRaw === "all" || portRaw === "full" || portRaw === "1-65535") {
      return { cleanTarget: targetPart, customPorts: "1-65535", isFullPort: true };
    }
    return { cleanTarget: targetPart, customPorts: portRaw.replace(/\s+/g, ""), isFullPort: false };
  }

  // Check colon / whitespace suffix: target:80,443 or target:all or target:1-65535 or target 80,443
  // Note: We need to differentiate CIDR mask e.g. 192.168.1.0/24 from ports
  const colonMatch = line.match(/^(.+?)(?::|\s+)(all|full|1-65535|\d{1,5}(?:(?:-\d{1,5})|(?:,\d{1,5}(?:-\d{1,5})?))*)$/i);
  if (colonMatch) {
    const targetPart = colonMatch[1].trim();
    const portRaw = colonMatch[2].trim().toLowerCase();
    if (portRaw === "all" || portRaw === "full" || portRaw === "1-65535") {
      return { cleanTarget: targetPart, customPorts: "1-65535", isFullPort: true };
    }
    return { cleanTarget: targetPart, customPorts: portRaw, isFullPort: false };
  }

  return { cleanTarget: line };
}

export function parseBatchTargets(
  rawText: string,
  maxTotalTargets: number = 512,
): ParseBatchResult {
  const lines = rawText
    .split(/[\r\n;；]+/)
    .map((line) => line.trim())
    .filter(Boolean);

  const seenValues = new Set<string>();
  const items: ParsedTargetItem[] = [];
  const errors: string[] = [];

  for (const line of lines) {
    if (items.length >= maxTotalTargets) {
      errors.push(`已达到单次解析最大数量上限（${maxTotalTargets} 个），超出部分已忽略`);
      break;
    }

    const { cleanTarget, customPorts, isFullPort } = extractPortSpec(line);

    // 1. URL pattern
    if (/^https?:\/\//i.test(cleanTarget)) {
      try {
        const url = new URL(cleanTarget);
        const canonical = url.origin;
        if (!seenValues.has(canonical)) {
          seenValues.add(canonical);
          items.push({
            id: `url-${items.length + 1}-${canonical}`,
            name: `站点-${url.hostname}`,
            targetValue: cleanTarget,
            targetType: "url",
            customPorts,
            isFullPort,
          });
        }
      } catch {
        errors.push(`无法解析 URL：${cleanTarget}`);
      }
      continue;
    }

    // 2. CIDR subnet (e.g. 192.168.1.0/24 or /28)
    const cidrMatch = cleanTarget.match(CIDR_REGEX);
    if (cidrMatch) {
      const baseIp = cidrMatch[1];
      const prefix = Number(cidrMatch[2]);
      if (prefix < 16 || prefix > 32) {
        errors.push(`CIDR 掩码 /${prefix} 过大或无效（仅支持 /16 至 /32）`);
        continue;
      }
      const hostCount = Math.pow(2, 32 - prefix);
      if (hostCount > 256) {
        errors.push(`网段 ${cleanTarget} 包含 ${hostCount} 个主机，超过单网段上限 256 台`);
        continue;
      }
      const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
      const startNum = (ipToNumber(baseIp) & mask) >>> 0;
      const endNum = (startNum + hostCount - 1) >>> 0;

      // In /24 or smaller, typically omit network .0 and broadcast .255 if hostCount > 2
      const firstUsable = hostCount > 2 ? startNum + 1 : startNum;
      const lastUsable = hostCount > 2 ? endNum - 1 : endNum;

      for (let num = firstUsable; num <= lastUsable; num++) {
        if (items.length >= maxTotalTargets) break;
        const ipStr = numberToIp(num);
        if (!seenValues.has(ipStr)) {
          seenValues.add(ipStr);
          items.push({
            id: `ip-${items.length + 1}-${ipStr}`,
            name: `主机-${ipStr}`,
            targetValue: ipStr,
            targetType: "ip",
            customPorts,
            isFullPort,
          });
        }
      }
      continue;
    }

    // 3. Full IP range: 192.168.1.10-192.168.1.25
    const fullRangeMatch = cleanTarget.match(IP_RANGE_FULL_REGEX);
    if (fullRangeMatch) {
      const startNum = ipToNumber(fullRangeMatch[1]);
      const endNum = ipToNumber(fullRangeMatch[2]);
      if (endNum < startNum) {
        errors.push(`IP 范围起始地址大于结束地址：${cleanTarget}`);
        continue;
      }
      if (endNum - startNum + 1 > 256) {
        errors.push(`IP 范围 ${cleanTarget} 跨度超过 256 台主机上限`);
        continue;
      }
      for (let num = startNum; num <= endNum; num++) {
        if (items.length >= maxTotalTargets) break;
        const ipStr = numberToIp(num);
        if (!seenValues.has(ipStr)) {
          seenValues.add(ipStr);
          items.push({
            id: `ip-${items.length + 1}-${ipStr}`,
            name: `主机-${ipStr}`,
            targetValue: ipStr,
            targetType: "ip",
            customPorts,
            isFullPort,
          });
        }
      }
      continue;
    }

    // 4. Short IP range: 192.168.1.10-25
    const shortRangeMatch = cleanTarget.match(IP_RANGE_SHORT_REGEX);
    if (shortRangeMatch) {
      const prefix = shortRangeMatch[1];
      const start = Number(shortRangeMatch[2]);
      const end = Number(shortRangeMatch[3]);
      if (start > 255 || end > 255 || start > end) {
        errors.push(`IP 范围无效：${cleanTarget}`);
        continue;
      }
      for (let octet = start; octet <= end; octet++) {
        if (items.length >= maxTotalTargets) break;
        const ipStr = `${prefix}${octet}`;
        if (!seenValues.has(ipStr)) {
          seenValues.add(ipStr);
          items.push({
            id: `ip-${items.length + 1}-${ipStr}`,
            name: `主机-${ipStr}`,
            targetValue: ipStr,
            targetType: "ip",
            customPorts,
            isFullPort,
          });
        }
      }
      continue;
    }

    // 5. Single IPv4
    if (IPV4_REGEX.test(cleanTarget)) {
      if (!seenValues.has(cleanTarget)) {
        seenValues.add(cleanTarget);
        items.push({
          id: `ip-${items.length + 1}-${cleanTarget}`,
          name: `主机-${cleanTarget}`,
          targetValue: cleanTarget,
          targetType: "ip",
          customPorts,
          isFullPort,
        });
      }
      continue;
    }

    // 6. Domain
    if (DOMAIN_REGEX.test(cleanTarget)) {
      if (!seenValues.has(cleanTarget)) {
        seenValues.add(cleanTarget);
        items.push({
          id: `domain-${items.length + 1}-${cleanTarget}`,
          name: `域名-${cleanTarget}`,
          targetValue: cleanTarget,
          targetType: "domain",
          customPorts,
          isFullPort,
        });
      }
      continue;
    }

    errors.push(`无法识别的目标格式：${line}`);
  }

  let ipCount = 0;
  let domainCount = 0;
  let urlCount = 0;
  let customPortCount = 0;
  for (const item of items) {
    if (item.targetType === "ip") ipCount++;
    else if (item.targetType === "domain") domainCount++;
    else if (item.targetType === "url") urlCount++;
    if (item.customPorts || item.isFullPort) customPortCount++;
  }

  return {
    items,
    stats: {
      total: items.length,
      ipCount,
      domainCount,
      urlCount,
      customPortCount,
    },
    errors,
  };
}
