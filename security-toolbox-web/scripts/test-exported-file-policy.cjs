// 第392轮：桌面「打开导出文件」策略的回归测试。
//
// exported-file-policy.cjs 是渲染进程 → 主进程唯一会"写文件并交给 shell.openPath()"的通道。
// 若允许 .exe/.bat/.ps1 或允许路径穿越，被攻陷的渲染进程即可获得本地代码执行。
// 本脚本锁定三类不变量：
//   1) 扩展名白名单：只有 .html/.htm/.pdf 通过；
//   2) 路径限定：文件名中的目录成分被剥离，目标必须落在下载目录内；
//   3) 体积与编码上限：超长/非法 base64 一律拒绝。
const assert = require("node:assert/strict");
const path = require("node:path");
const {
  ALLOWED_EXTENSIONS,
  MAX_EXPORTED_FILE_BYTES,
  prepareExportedFile,
} = require("../electron/exported-file-policy.cjs");

const downloads = path.join("C:", "Users", "tester", "Downloads");
const b64 = (text) => Buffer.from(text, "utf8").toString("base64");

let checks = 0;
const check = (name, fn) => {
  fn();
  checks += 1;
};

// —— 1. 扩展名白名单 ——
check("允许的报告类型", () => {
  for (const name of ["report.html", "report.htm", "report.pdf"]) {
    const prepared = prepareExportedFile({ filename: name, base64: b64("ok") }, downloads);
    assert.ok(prepared, `${name} 应被允许`);
    assert.equal(path.dirname(prepared.targetPath), path.resolve(downloads));
    assert.equal(path.basename(prepared.targetPath), name);
  }
  assert.deepEqual(ALLOWED_EXTENSIONS.sort(), [".htm", ".html", ".pdf"].sort());
});

check("拒绝可执行与脚本类型", () => {
  for (const name of [
    "payload.exe",
    "payload.bat",
    "payload.ps1",
    "payload.cmd",
    "payload.js",
    "payload.vbs",
    "payload.scr",
    "payload.dll",
    "payload.jar",
    "payload.msi",
    "payload",
    "payload.pdf.exe",
  ]) {
    assert.equal(
      prepareExportedFile({ filename: name, base64: b64("no") }, downloads),
      null,
      `${name} 必须被拒绝`,
    );
  }
});

check("大写扩展名按小写判定", () => {
  assert.ok(prepareExportedFile({ filename: "REPORT.PDF", base64: b64("x") }, downloads));
  assert.equal(prepareExportedFile({ filename: "EVIL.EXE", base64: b64("x") }, downloads), null);
});

// —— 2. 路径限定 ——
check("目录成分被剥离，目标始终落在下载目录内", () => {
  const cases = [
    "../../evil.pdf",
    "..\\..\\evil.pdf",
    "/etc/passwd.pdf",
    "C:\\Windows\\System32\\evil.pdf",
    "sub/dir/evil.pdf",
  ];
  for (const filename of cases) {
    const prepared = prepareExportedFile({ filename, base64: b64("x") }, downloads);
    assert.ok(prepared, `${filename} 应被规整后允许`);
    assert.equal(
      path.dirname(prepared.targetPath),
      path.resolve(downloads),
      `${filename} 的目标必须仍在下载目录内`,
    );
    assert.ok(!path.basename(prepared.targetPath).includes(".."));
    assert.ok(!path.basename(prepared.targetPath).includes("/"));
    assert.ok(!path.basename(prepared.targetPath).includes("\\"));
  }
});

check("Windows 非法字符被替换，不会产生意外路径", () => {
  const prepared = prepareExportedFile({ filename: 'a:b*c?d"e<f>g|h.pdf', base64: b64("x") }, downloads);
  assert.ok(prepared);
  assert.equal(path.dirname(prepared.targetPath), path.resolve(downloads));
  assert.ok(!/[\\/:*?"<>|]/.test(path.basename(prepared.targetPath)));
});

check("缺省文件名安全（不提供 filename 时用默认报告名）", () => {
  const prepared = prepareExportedFile({ base64: b64("x") }, downloads);
  assert.ok(prepared);
  assert.equal(path.basename(prepared.targetPath), "security-report.pdf");
});

// —— 3. 体积与编码上限 ——
check("拒绝空/非法 base64", () => {
  assert.equal(prepareExportedFile({ filename: "r.pdf" }, downloads), null);
  assert.equal(prepareExportedFile({ filename: "r.pdf", base64: "" }, downloads), null);
  assert.equal(prepareExportedFile({ filename: "r.pdf", base64: "!!!!" }, downloads), null);
  assert.equal(prepareExportedFile({ filename: "r.pdf", base64: "abc" }, downloads), null); // 长度非 4 的倍数
  assert.equal(prepareExportedFile({ filename: "r.pdf", base64: "aGVsbG8===" }, downloads), null);
});

check("拒绝超限 payload（在分配缓冲区之前就判掉）", () => {
  const overEncodedLimit = "A".repeat(Math.ceil((MAX_EXPORTED_FILE_BYTES * 4) / 3) + 16);
  assert.equal(prepareExportedFile({ filename: "r.pdf", base64: overEncodedLimit }, downloads), null);
});

check("拒绝非对象 payload", () => {
  for (const payload of [null, undefined, "string", 42, []]) {
    if (Array.isArray(payload)) continue; // 数组无 filename/base64，走默认分支返回 null
    assert.equal(prepareExportedFile(payload, downloads), null);
  }
  assert.equal(prepareExportedFile([], downloads), null);
});

console.log(`exported-file-policy 策略测试通过：${checks} 组断言`);
