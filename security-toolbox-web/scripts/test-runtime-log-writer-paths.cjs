// 第393轮：运行日志写入器的路径安全回归测试。
//
// runtime-log-writer.cjs 会把 component 拼进文件名（`${component}-${sessionId}.log`）。
// 若 component 未校验，`../` 之类的取值会让日志写到目标目录之外——这是本地覆盖文件/提权的常见入口。
// 本脚本锁定：
//   1) component 必须匹配 ^[a-z0-9][a-z0-9.-]{0,63}$（拒绝斜杠、`..`、绝对路径、大写、空值）；
//   2) 实际写入的文件必须落在指定目录内；
//   3) 单卷大小与队列上限必须是正整数（防止用 0/负数把保护关掉）。
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { RuntimeLogWriter } = require("../electron/runtime-log-writer.cjs");

let checks = 0;
const check = (name, fn) => {
  fn();
  checks += 1;
  console.log(`  ✓ ${name}`);
};

async function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "security-toolbox-log-paths-"));
  try {
    check("拒绝可穿越/非法的 component", () => {
      const bad = [
        "../escape",
        "..\\escape",
        "a/b",
        "a\\b",
        "../../etc/passwd",
        "C:\\Windows\\System32",
        "/absolute",
        "",
        "UPPER",
        "with space",
        "with_underscore",
        ".hidden",
        "-leading-dash",
        "..",
        "a".repeat(65),
      ];
      for (const component of bad) {
        assert.throws(
          () => new RuntimeLogWriter({ directory: tempRoot, component }),
          /Invalid log component/,
          `component=${JSON.stringify(component)} 必须被拒绝`,
        );
      }
    });

    check("接受合法的 component 形态", () => {
      for (const component of ["app", "ai-relay", "backend.1", "a1", "x".repeat(64)]) {
        const writer = new RuntimeLogWriter({ directory: tempRoot, component });
        assert.equal(writer.component, component);
      }
    });

    check("非法上限被拒绝（不能把保护关成 0 或负数）", () => {
      for (const value of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, "1024"]) {
        assert.throws(
          () => new RuntimeLogWriter({ directory: tempRoot, component: "app", maxVolumeBytes: value }),
          /maxVolumeBytes must be a positive integer/,
          `maxVolumeBytes=${String(value)} 必须被拒绝`,
        );
      }
      assert.throws(
        () => new RuntimeLogWriter({ directory: tempRoot, component: "app", maxQueueBytes: 0 }),
        /maxQueueBytes must be a positive integer/,
      );
    });

    check("缺少 directory 被拒绝", () => {
      assert.throws(() => new RuntimeLogWriter({ component: "app" }), /directory is required/);
      assert.throws(() => new RuntimeLogWriter(), /directory is required/);
    });

    // 真实写入：文件必须落在目录内、文件名带合法前缀
    const writer = new RuntimeLogWriter({
      directory: tempRoot,
      component: "app",
      maxVolumeBytes: 4096,
      maxQueueBytes: 4096,
    });
    writer.write("第一行日志\n");
    writer.write("second line\n");
    await writer.close();

    const entries = fs.readdirSync(tempRoot);
    assert.ok(entries.length > 0, "应至少产生一个日志文件");
    for (const name of entries) {
      const full = path.join(tempRoot, name);
      assert.equal(path.dirname(full), tempRoot, `${name} 必须位于日志目录内`);
      assert.ok(!name.includes(".."), `${name} 不得包含上级引用`);
      assert.ok(name.startsWith("app-"), `文件名应带合法前缀: ${name}`);
      assert.ok(!fs.statSync(full).isDirectory(), `${name} 不应该是目录`);
    }
    checks += 1;
    console.log(`  ✓ 实际写入的 ${entries.length} 个文件全部位于日志目录内`);

    console.log(`runtime-log-writer 路径安全测试通过：${checks} 组断言`);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
