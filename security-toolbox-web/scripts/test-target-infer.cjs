const assert = require("node:assert");

function inferTargetType(value) {
  const trimmed = (value || "").trim();
  if (!trimmed) return null;
  if (/^https?:\/\//i.test(trimmed)) {
    return "url";
  }
  const ipv4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  if (ipv4.test(trimmed)) {
    return "ip";
  }
  const domain =
    /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,}$/i;
  if (domain.test(trimmed) && trimmed.includes(".")) {
    return "domain";
  }
  return null;
}

function validateDomainTarget(value, targetType) {
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

console.log("Testing inferTargetType and validateDomainTarget...");

// 1. inferTargetType assertions
assert.strictEqual(inferTargetType("192.168.222.133"), "ip");
assert.strictEqual(inferTargetType("http://192.168.222.133:80"), "url");
assert.strictEqual(inferTargetType("example.com"), "domain");
assert.strictEqual(inferTargetType("999.999.999.999"), null);

// 2. validateDomainTarget positive tests
assert.doesNotThrow(() => validateDomainTarget("192.168.222.133", "ip"));
assert.doesNotThrow(() => validateDomainTarget("10.0.0.1", "IP"));
assert.doesNotThrow(() => validateDomainTarget("http://192.168.222.133:80", "url"));
assert.doesNotThrow(() => validateDomainTarget("https://target.com/api", "URL"));
assert.doesNotThrow(() => validateDomainTarget("sec.example.com", "domain"));

// 3. validateDomainTarget negative tests (FZT-07, FZT-09, etc.)
assert.throws(() => validateDomainTarget("192.168.222.133.", "ip"), /IP 地址格式不正确/);
assert.throws(() => validateDomainTarget("http://192.168.222.133/admin?id=1", "ip"), /IP 地址格式不正确/);
assert.throws(() => validateDomainTarget("1.2.3.4.5", "ip"), /IP 地址格式不正确/);
assert.throws(() => validateDomainTarget("not_a_url", "url"), /URL 格式不正确/);
assert.throws(() => validateDomainTarget("invalid domain with spaces", "domain"), /域名格式不正确/);

console.log("All frontend target validation unit tests passed!");
