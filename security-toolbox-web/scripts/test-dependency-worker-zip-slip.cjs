// 第394轮：依赖包解压的 Zip Slip 防护回归测试。
//
// dependency-worker.cjs 用 adm-zip 解压下载的工具包（nuclei/httpx/afrog/xray/sqlmap 等）。
// 若条目名未经校验，恶意/被投毒的压缩包里 `../` 条目可以写到安装目录之外（Zip Slip，可覆盖任意可写文件，
// 常见提权/持久化手法）。安全判定集中在 safeArchiveEntryName()。
//
// 本脚本直接 require 生产实现（不是副本），断言：
//   1) 拒绝 `../` 遍历（含反斜杠形式）、绝对路径、NUL 字节、空段、空串；
//   2) 接受常规文件名与合法的多级路径，并返回归一化后的 POSIX 形式。
const assert = require("node:assert/strict");
const { safeArchiveEntryName } = require("../electron/archive-entry-policy.cjs");

let checks = 0;
const check = (name, fn) => {
  fn();
  checks += 1;
  console.log(`  ✓ ${name}`);
};

try {
  check("拒绝 Zip Slip 与非法条目名", () => {
    const bad = [
      "../evil.exe",
      "../../evil.exe",
      "..\\evil.exe",
      "dir/../../evil.exe",
      "dir\\..\\..\\evil.exe",
      "/etc/passwd",
      "\\\\server\\share\\evil.exe",
      "a//b.txt",
      "a/",
      "",
      null,
      undefined,
      "bad\0name.txt",
    ];
    for (const entry of bad) {
      assert.equal(
        safeArchiveEntryName(entry),
        undefined,
        `条目 ${JSON.stringify(entry)} 必须被拒绝`,
      );
    }
  });

  check("接受常规文件名与合法多级路径", () => {
    const good = [
      "nuclei.exe",
      "nuclei_3.4.10_windows_amd64/nuclei.exe",
      "a/b/c.txt",
      "带中文名.txt",
      "file with space.txt",
    ];
    for (const entry of good) {
      const result = safeArchiveEntryName(entry);
      assert.ok(result, `条目 ${JSON.stringify(entry)} 应被接受`);
      assert.equal(typeof result.normalized, "string");
      assert.ok(Array.isArray(result.parts) && result.parts.length > 0);
      assert.ok(!result.normalized.includes("\\"), "归一化结果必须是 POSIX 分隔符");
      assert.ok(!result.normalized.startsWith("/"), "归一化结果不得是绝对路径");
      assert.ok(!result.parts.includes(".."), "归一化结果不得包含上级引用");
      assert.equal(result.normalized, result.parts.join("/"));
    }
  });

  check("反斜杠形式被归一化为 POSIX 分隔符", () => {
    const result = safeArchiveEntryName("dir\\sub\\file.exe");
    assert.ok(result);
    assert.equal(result.normalized, "dir/sub/file.exe");
    assert.deepEqual(result.parts, ["dir", "sub", "file.exe"]);
  });

  check("拒绝反斜杠形式的穿越（归一化后再判定）", () => {
    assert.equal(safeArchiveEntryName("dir\\..\\..\\evil.exe"), undefined);
    assert.equal(safeArchiveEntryName("..\\..\\evil.exe"), undefined);
  });

  console.log(`dependency-worker Zip Slip 防护测试通过：${checks} 组断言`);
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
