/*
 * 阶段 L：离线工具集（22 个本地工具）
 *
 * 约束：全部操作均为真实 UI 交互（点击工具索引、输入文本、选择下拉、勾选复选框、
 * 选择本地文件），不调用任何后端 API，也不用 page.evaluate 代替业务逻辑。
 * page.evaluate 仅在读取无可视表现的状态时使用（本模块未使用）。
 *
 * 断言口径：所有期望值由 Node 侧独立实现（node:crypto / Buffer / 已知向量）计算，
 * 与页面实现相互印证，而不是复用前端代码。
 */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  sleep, settle, navigate, pageTitle, selectOn, lastMessage, clearMessages, escapeRe,
} = require("../lib/ui.cjs");

const TMP_DIR = "test-data/tmp";

/* ------------------------------------------------------------------ */
/* 断言与小工具                                                        */
/* ------------------------------------------------------------------ */

function must(condition, message) {
  if (!condition) throw new Error(message);
}

function eq(actual, expected, what) {
  if (actual !== expected) {
    throw new Error(`${what} 期望 "${String(expected).slice(0, 200)}"，实际 "${String(actual).slice(0, 200)}"`);
  }
}

function contains(haystack, needle, what) {
  if (!String(haystack).includes(needle)) {
    throw new Error(`${what} 应包含 "${needle}"，实际 "${String(haystack).slice(0, 300)}"`);
  }
}

function shorten(value, n = 60) {
  const s = String(value == null ? "" : value).replace(/\s+/g, " ").trim();
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/* ------------------------------------------------------------------ */
/* 页面定位原语                                                        */
/* ------------------------------------------------------------------ */

/** 通过左侧索引点击切换工具，返回工作台容器定位器 */
async function selectTool(page, name) {
  const index = page.locator("aside.offline-tool-index");
  const item = index
    .locator("button.offline-tool-item")
    .filter({ has: page.locator("strong", { hasText: new RegExp(`^${escapeRe(name)}$`) }) })
    .first();
  await item.waitFor({ state: "visible", timeout: 12000 });
  await item.click();
  await page
    .locator(".offline-workbench-head h2")
    .filter({ hasText: new RegExp(`^${escapeRe(name)}$`) })
    .first()
    .waitFor({ state: "visible", timeout: 10000 });
  await sleep(250);
  return page.locator("section.offline-workbench");
}

/** 按 <label> 文本精确定位（label 内即为该字段的输入控件） */
function labelBox(scope, text) {
  return scope
    .locator("label")
    .filter({ hasText: new RegExp(`^\\s*${escapeRe(text)}\\s*$`) })
    .first();
}

function labelArea(scope, text) {
  return labelBox(scope, text).locator("textarea").first();
}

function labelInput(scope, text) {
  return labelBox(scope, text).locator("input").first();
}

/** 下拉框所在 label 文本会混入已选项文案，因此用子串匹配 */
function labelSelect(scope, text) {
  return scope.locator("label").filter({ hasText: text }).first().locator(".el-select").first();
}

function button(scope, text) {
  return scope.locator("button").filter({ hasText: new RegExp(`^\\s*${escapeRe(text)}\\s*$`) }).first();
}

/** 轮询等待输入框取值满足条件（用于 WebCrypto 等异步计算） */
async function waitValue(locator, predicate, { timeout = 20000, what = "取值" } = {}) {
  const start = Date.now();
  let last = "";
  while (Date.now() - start < timeout) {
    last = (await locator.inputValue().catch(() => "")) || "";
    if (predicate(last)) return last;
    await sleep(200);
  }
  throw new Error(`${what} 等待超时，最后取值="${shorten(last, 160)}"`);
}

/** 勾选/取消勾选 Element Plus 复选框，使其到达期望状态 */
async function setCheckbox(scope, text, checked) {
  const box = scope.locator(".el-checkbox").filter({ hasText: new RegExp(`^\\s*${escapeRe(text)}\\s*$`) }).first();
  await box.waitFor({ state: "visible", timeout: 8000 });
  const cls = (await box.getAttribute("class")) || "";
  if (cls.includes("is-checked") !== checked) {
    await box.click();
    await sleep(180);
  }
}

/** 多选下拉：依次点击若干选项完成勾选/取消 */
async function toggleMultiOptions(page, selectLocator, labels) {
  await selectLocator.click();
  await sleep(450);
  const dropdown = page.locator(".el-select-dropdown:visible").last();
  await dropdown.waitFor({ state: "visible", timeout: 8000 });
  for (const label of labels) {
    const option = dropdown
      .locator("li.el-select-dropdown__item")
      .filter({ hasText: new RegExp(`^\\s*${escapeRe(label)}\\s*$`) })
      .first();
    await option.waitFor({ state: "visible", timeout: 8000 });
    await option.click();
    await sleep(220);
  }
  await page.keyboard.press("Escape").catch(() => {});
  await sleep(350);
}

/* ------------------------------------------------------------------ */
/* 独立计算的期望值（Node 侧实现，不复用前端代码）                       */
/* ------------------------------------------------------------------ */

const CODEC_TEXT = "Hello獬豸";
const EXPECT = {
  base64: Buffer.from(CODEC_TEXT, "utf8").toString("base64"),
  base64url: Buffer.from(CODEC_TEXT, "utf8").toString("base64url"),
  hex: Buffer.from(CODEC_TEXT, "utf8").toString("hex"),
  url: encodeURIComponent(CODEC_TEXT),
  md5abc: crypto.createHash("md5").update("abc").digest("hex"),
  sha1abc: crypto.createHash("sha1").update("abc").digest("hex"),
  sha256abc: crypto.createHash("sha256").update("abc").digest("hex"),
  sha384abc: crypto.createHash("sha384").update("abc").digest("hex"),
  sha512abc: crypto.createHash("sha512").update("abc").digest("hex"),
  hmac: crypto.createHmac("sha256", "xiezhi-e2e-key").update("abc").digest("hex"),
};

const XSS_PAYLOAD = "<scr" + "ipt>alert(1)</scr" + "ipt>";
const XSS_URL_ENCODED = encodeURIComponent(XSS_PAYLOAD);
const XSS_URL_BASE64 = Buffer.from(XSS_URL_ENCODED, "utf8").toString("base64");

const JWT_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
  ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
  ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

/* ------------------------------------------------------------------ */
/* 临时文件夹具                                                        */
/* ------------------------------------------------------------------ */

function writeFixtures() {
  fs.mkdirSync(TMP_DIR, { recursive: true });

  const textBuf = Buffer.from("Xiezhi offline toolbox e2e sample.\n", "utf8");
  const textFile = path.join(TMP_DIR, "l-file-sample.txt");
  fs.writeFileSync(textFile, textBuf);

  // 伪造 PNG：仅头部魔数真实，用于验证魔数推断
  const pngBuf = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.from([0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52]),
    Buffer.from("XIEZHI-FAKE-PNG-BODY", "ascii"),
  ]);
  const pngFile = path.join(TMP_DIR, "l-file-magic.png");
  fs.writeFileSync(pngFile, pngBuf);

  // 十六进制查看器夹具：75 行 × 16 字节 = 1200 字节，内容自描述便于逐行断言
  const lines = [];
  for (let i = 0; i < 75; i += 1) lines.push(`XIEZHI-HEX-${String(i).padStart(4, "0")} `);
  const hexBuf = Buffer.from(lines.join(""), "ascii");
  const hexFile = path.join(TMP_DIR, "l-hex-sample.bin");
  fs.writeFileSync(hexFile, hexBuf);

  return {
    textFile,
    textBuf,
    textHashes: {
      MD5: crypto.createHash("md5").update(textBuf).digest("hex"),
      "SHA-1": crypto.createHash("sha1").update(textBuf).digest("hex"),
      "SHA-256": crypto.createHash("sha256").update(textBuf).digest("hex"),
      "SHA-512": crypto.createHash("sha512").update(textBuf).digest("hex"),
    },
    pngFile,
    pngBuf,
    hexFile,
    hexBuf,
  };
}

/* ================================================================== */
/* 主流程                                                              */
/* ================================================================== */

async function run(page, H, ctx) {
  H.phase("阶段 L — 离线工具集");

  const fixtures = writeFixtures();
  const workbench = () => page.locator("section.offline-workbench");

  /* ---------------- L-01 ~ L-06：页面框架与索引 ---------------- */

  await H.run("L-01", "从侧边栏进入离线工具集页面", async () => {
    await navigate(page, "离线工具集");
    await page.locator(".offline-tools-page").first().waitFor({ state: "visible", timeout: 15000 });
    const h1 = (await page.locator(".offline-tools-heading h1").first().textContent()) || "";
    eq(h1.trim(), "离线工具集", "页面主标题");
    const title = await pageTitle(page);
    contains(title, "离线工具", "顶栏页面标题");
    must(page.url().includes("/offline-tools"), `URL 未进入离线工具集，当前 ${page.url()}`);
    return `标题="${h1.trim()}" URL=${page.url()}`;
  }, { page });

  await H.run("L-02", "左侧索引渲染 6 个分组共 22 个工具", async () => {
    const aside = page.locator("aside.offline-tool-index");
    await aside.waitFor({ state: "visible", timeout: 10000 });
    const groups = await aside.locator(".offline-tool-groups > section").count();
    const items = await aside.locator("button.offline-tool-item").count();
    eq(groups, 6, "工具分组数量");
    eq(items, 22, "工具条目数量");
    const active = await aside.locator("button.offline-tool-item.active strong").first().textContent();
    eq((active || "").trim(), "编码转换", "默认选中的工具");
    return `分组 ${groups} 个、工具 ${items} 个，默认选中「编码转换」`;
  }, { page });

  await H.run("L-03", "顶栏上下文提示为「输入仅在本机处理」", async () => {
    const text = (await page.locator(".desktop-v2-context").first().textContent()) || "";
    contains(text.replace(/\s+/g, ""), "输入仅在本机处理", "顶栏上下文");
    return `顶栏上下文="${text.trim().replace(/\s+/g, " ")}"`;
  }, { page });

  await H.run("L-04", "隐私徽标提示「输入内容不会上传」", async () => {
    const badge = page.locator(".offline-privacy-badge").first();
    await badge.waitFor({ state: "visible", timeout: 8000 });
    const text = ((await badge.textContent()) || "").trim();
    eq(text, "输入内容不会上传", "隐私徽标文案");
    return `徽标="${text}"`;
  }, { page });

  await H.run("L-05", "搜索框按关键字过滤工具索引", async () => {
    const search = page.locator('input[aria-label="搜索离线工具"]');
    await search.waitFor({ state: "visible", timeout: 8000 });
    await search.fill("bcrypt");
    await sleep(500);
    const names = await page.locator("aside.offline-tool-index button.offline-tool-item strong").allTextContents();
    eq(names.length, 1, "关键字 bcrypt 命中的工具数量");
    eq(names[0].trim(), "哈希类型识别", "命中的工具名称");

    await search.fill("cidr");
    await sleep(500);
    const names2 = await page.locator("aside.offline-tool-index button.offline-tool-item strong").allTextContents();
    eq(names2.length, 1, "关键字 cidr 命中的工具数量");
    eq(names2[0].trim(), "IPv4 / CIDR 计算", "命中的工具名称");
    return "bcrypt→哈希类型识别，cidr→IPv4 / CIDR 计算";
  }, { page });

  await H.run("L-06", "搜索无结果时展示空状态，清除按钮恢复全部工具", async () => {
    const search = page.locator('input[aria-label="搜索离线工具"]');
    await search.fill("zzz-no-such-tool");
    await sleep(500);
    const empty = page.locator(".offline-tool-empty").first();
    await empty.waitFor({ state: "visible", timeout: 6000 });
    eq(((await empty.textContent()) || "").trim(), "没有匹配的工具", "空状态文案");
    eq(await page.locator("aside.offline-tool-index button.offline-tool-item").count(), 0, "空状态下的工具数量");

    const clear = page.locator("button.offline-tool-search-clear").first();
    await clear.waitFor({ state: "visible", timeout: 6000 });
    await clear.click();
    await sleep(500);
    eq(await search.inputValue(), "", "清除后搜索框内容");
    eq(await page.locator("aside.offline-tool-index button.offline-tool-item").count(), 22, "清除后的工具数量");
    return "空状态文案正确，清除后恢复 22 个工具";
  }, { page });

  await H.shot(page, "L-页面总览");

  /* ---------------- 编码转换 ---------------- */

  await H.run("L-07", "编码转换：Base64 编码中英文混合文本", async () => {
    const w = await selectTool(page, "编码转换");
    await selectOn(page, labelSelect(w, "编码类型"), "Base64", { exact: true });
    await labelArea(w, "输入").fill(CODEC_TEXT);
    await button(w, "编码").click();
    await sleep(400);
    const out = await labelArea(w, "结果").inputValue();
    eq(out, EXPECT.base64, "Base64 编码结果");
    return `编码结果=${out}`;
  }, { page });

  await H.run("L-08", "编码转换：交换后解码可还原原文", async () => {
    const w = workbench();
    await button(w, "交换").click();
    await sleep(300);
    eq(await labelArea(w, "输入").inputValue(), EXPECT.base64, "交换后输入框内容");
    await button(w, "解码").click();
    await sleep(400);
    const out = await labelArea(w, "结果").inputValue();
    eq(out, CODEC_TEXT, "Base64 解码结果");
    return `解码还原=${out}`;
  }, { page });

  await H.run("L-09", "编码转换：Hex 十六进制编解码往返", async () => {
    const w = workbench();
    await selectOn(page, labelSelect(w, "编码类型"), "Hex 十六进制", { exact: true });
    await labelArea(w, "输入").fill(CODEC_TEXT);
    await button(w, "编码").click();
    await sleep(400);
    const hex = await labelArea(w, "结果").inputValue();
    eq(hex, EXPECT.hex, "Hex 编码结果");
    await labelArea(w, "输入").fill(hex);
    await button(w, "解码").click();
    await sleep(400);
    eq(await labelArea(w, "结果").inputValue(), CODEC_TEXT, "Hex 解码结果");
    return `Hex=${hex}，解码还原成功`;
  }, { page });

  await H.run("L-10", "编码转换：URL 百分号编码与 HTML 实体编码", async () => {
    const w = workbench();
    await selectOn(page, labelSelect(w, "编码类型"), "URL 百分号编码", { exact: true });
    await labelArea(w, "输入").fill(CODEC_TEXT);
    await button(w, "编码").click();
    await sleep(400);
    const urlOut = await labelArea(w, "结果").inputValue();
    eq(urlOut, EXPECT.url, "URL 编码结果");

    await selectOn(page, labelSelect(w, "编码类型"), "HTML 实体", { exact: true });
    await labelArea(w, "输入").fill('<a href="x">O\'K & Co</a>');
    await button(w, "编码").click();
    await sleep(400);
    const htmlOut = await labelArea(w, "结果").inputValue();
    eq(
      htmlOut,
      "&lt;a href=&quot;x&quot;&gt;O&#39;K &amp; Co&lt;/a&gt;",
      "HTML 实体编码结果",
    );
    return `URL=${urlOut}；HTML 实体编码正确`;
  }, { page });

  await H.run("L-11", "编码转换：Base64 URL Safe 去除填充并替换 +/ 字符", async () => {
    const w = workbench();
    await selectOn(page, labelSelect(w, "编码类型"), "Base64 URL Safe", { exact: true });
    await labelArea(w, "输入").fill(CODEC_TEXT);
    await button(w, "编码").click();
    await sleep(400);
    const out = await labelArea(w, "结果").inputValue();
    eq(out, EXPECT.base64url, "Base64 URL Safe 编码结果");
    must(!/[+/=]/.test(out), `URL Safe 结果不应包含 + / = 字符，实际 ${out}`);
    must(EXPECT.base64 !== out, "URL Safe 结果应与标准 Base64 不同");
    return `URLSafe=${out}（标准 Base64=${EXPECT.base64}）`;
  }, { page });

  await H.run("L-12", "编码转换：过滤中文字符开关生效", async () => {
    const w = workbench();
    await selectOn(page, labelSelect(w, "编码类型"), "Base64", { exact: true });
    await setCheckbox(w, "过滤中文字符", true);
    await labelArea(w, "输入").fill(CODEC_TEXT);
    await button(w, "编码").click();
    await sleep(400);
    const out = await labelArea(w, "结果").inputValue();
    eq(out, Buffer.from("Hello", "utf8").toString("base64"), "过滤中文后编码结果");
    await setCheckbox(w, "过滤中文字符", false);
    return `过滤中文后 "${CODEC_TEXT}" → ${out}（等价于 "Hello"）`;
  }, { page });

  await H.run("L-13", "编码转换：复制结果提示与清空按钮", async () => {
    const w = workbench();
    await clearMessages(page);
    await button(w, "复制结果").click();
    const msg = await lastMessage(page, { timeout: 8000 });
    must(msg && msg.type === "success", `复制未出现成功提示，实际 ${msg && msg.type}: ${msg && msg.text}`);
    contains(msg.text, "已复制", "复制提示文案");
    await clearMessages(page);
    await button(w, "清空").click();
    await sleep(300);
    eq(await labelArea(w, "输入").inputValue(), "", "清空后的输入框");
    eq(await labelArea(w, "结果").inputValue(), "", "清空后的结果框");
    return `复制提示="${msg.text}"，清空后两个文本框均为空`;
  }, { page });

  await H.shot(page, "L-编码转换");

  /* ---------------- 哈希与 HMAC ---------------- */

  await H.run("L-14", "哈希与 HMAC：abc 的 MD5/SHA 系列摘要与已知向量一致", async () => {
    const w = await selectTool(page, "哈希与 HMAC");
    await labelArea(w, "原文").fill("abc");
    await button(w, "计算摘要").click();
    await page.locator(".hash-results article").first().waitFor({ state: "visible", timeout: 15000 });
    await sleep(400);
    const read = async (name) => {
      const card = w.locator(".hash-results article")
        .filter({ has: page.locator("strong", { hasText: new RegExp(`^${escapeRe(name)}$`) }) })
        .first();
      return ((await card.locator("code").first().textContent()) || "").trim();
    };
    eq(await read("MD5"), EXPECT.md5abc, "MD5(abc)");
    eq(await read("SHA-1"), EXPECT.sha1abc, "SHA-1(abc)");
    eq(await read("SHA-256"), EXPECT.sha256abc, "SHA-256(abc)");
    eq(await read("SHA-384"), EXPECT.sha384abc, "SHA-384(abc)");
    eq(await read("SHA-512"), EXPECT.sha512abc, "SHA-512(abc)");
    return `SHA-256(abc)=${EXPECT.sha256abc}，五种摘要全部匹配`;
  }, { page });

  await H.run("L-15", "哈希与 HMAC：填写密钥后额外计算 HMAC-SHA256", async () => {
    const w = workbench();
    await labelInput(w, "HMAC 密钥（可选）").fill("xiezhi-e2e-key");
    await button(w, "计算摘要").click();
    await sleep(1200);
    const card = w.locator(".hash-results article")
      .filter({ has: page.locator("strong", { hasText: /^HMAC-SHA256$/ }) })
      .first();
    await card.waitFor({ state: "visible", timeout: 12000 });
    const value = ((await card.locator("code").first().textContent()) || "").trim();
    eq(value, EXPECT.hmac, "HMAC-SHA256(abc, xiezhi-e2e-key)");
    return `HMAC-SHA256=${value}`;
  }, { page });

  await H.shot(page, "L-哈希与HMAC");

  /* ---------------- AES 加解密 ---------------- */

  const AES_PLAIN = "獬豸离线加密测试-2026";
  const AES_PASSWORD = "S3cret-Passphrase!";

  await H.run("L-16", "AES 加解密：加密输出 AES-256-GCM 加密包结构", async () => {
    const w = await selectTool(page, "AES 加解密");
    await labelInput(w, "加密口令").fill(AES_PASSWORD);
    await labelArea(w, "输入").fill(AES_PLAIN);
    await button(w, "加密").click();
    const raw = await waitValue(labelArea(w, "结果"), (v) => v.trim().startsWith("{"), { timeout: 25000, what: "AES 加密结果" });
    const pkg = JSON.parse(raw);
    eq(pkg.version, 1, "加密包版本");
    eq(pkg.algorithm, "AES-GCM", "加密算法");
    eq(pkg.iterations, 210000, "PBKDF2 迭代次数");
    must(Buffer.from(pkg.salt, "base64").length === 16, `salt 应为 16 字节，实际 ${Buffer.from(pkg.salt, "base64").length}`);
    must(Buffer.from(pkg.iv, "base64").length === 12, `iv 应为 12 字节，实际 ${Buffer.from(pkg.iv, "base64").length}`);
    // GCM 密文 = 明文字节 + 16 字节认证标签
    const plainBytes = Buffer.from(AES_PLAIN, "utf8").length;
    eq(Buffer.from(pkg.ciphertext, "base64").length, plainBytes + 16, "密文长度（明文+GCM 标签）");
    ctx.offlineAesPackage = raw;
    return `algorithm=${pkg.algorithm}, iterations=${pkg.iterations}, salt=16B, iv=12B, ciphertext=${plainBytes + 16}B`;
  }, { page });

  await H.run("L-17", "AES 加解密：相同明文两次加密的密文不同（随机盐/IV）", async () => {
    const w = workbench();
    await labelArea(w, "输入").fill(AES_PLAIN);
    await button(w, "加密").click();
    const second = await waitValue(
      labelArea(w, "结果"),
      (v) => v.trim().startsWith("{") && v !== ctx.offlineAesPackage,
      { timeout: 25000, what: "第二次 AES 加密结果" },
    );
    const a = JSON.parse(ctx.offlineAesPackage);
    const b = JSON.parse(second);
    must(a.salt !== b.salt, "两次加密的盐不应相同");
    must(a.iv !== b.iv, "两次加密的 IV 不应相同");
    must(a.ciphertext !== b.ciphertext, "两次加密的密文不应相同");
    ctx.offlineAesPackage = second;
    return `盐/IV/密文三者均不同（salt: ${a.salt.slice(0, 8)}… vs ${b.salt.slice(0, 8)}…）`;
  }, { page });

  await H.run("L-18", "AES 加解密：口令正确时解密还原原文", async () => {
    const w = workbench();
    await button(w, "将结果作为输入").click();
    await sleep(300);
    eq(await labelArea(w, "结果").inputValue(), "", "转入输入后结果框应清空");
    await button(w, "解密").click();
    const out = await waitValue(labelArea(w, "结果"), (v) => v.length > 0, { timeout: 25000, what: "AES 解密结果" });
    eq(out, AES_PLAIN, "AES 解密还原的明文");
    return `解密还原=${out}`;
  }, { page });

  await H.run("L-19", "AES 加解密：口令错误时解密失败并提示", async () => {
    const w = workbench();
    await labelArea(w, "输入").fill(ctx.offlineAesPackage);
    await labelInput(w, "加密口令").fill("wrong-passphrase");
    await clearMessages(page);
    await button(w, "解密").click();
    const msg = await lastMessage(page, { timeout: 25000 });
    must(msg && msg.type === "error", `错误口令应出现错误提示，实际 ${msg && msg.type}: ${msg && msg.text}`);
    contains(msg.text, "解密失败", "错误提示文案");
    await clearMessages(page);
    return `错误口令提示="${msg.text}"`;
  }, { page });

  await H.shot(page, "L-AES加解密");

  /* ---------------- 古典密码 ---------------- */

  await H.run("L-20", "古典密码：ROT13 加密 Hello 得到 Uryyb", async () => {
    const w = await selectTool(page, "古典密码");
    await selectOn(page, labelSelect(w, "算法"), "ROT13", { exact: true });
    await labelArea(w, "输入").fill("Hello");
    await button(w, "加密").click();
    await sleep(300);
    eq(await labelArea(w, "结果").inputValue(), "Uryyb", "ROT13(Hello)");
    return "ROT13(Hello)=Uryyb";
  }, { page });

  await H.run("L-21", "古典密码：凯撒位移 5 加解密往返", async () => {
    const w = workbench();
    await selectOn(page, labelSelect(w, "算法"), "凯撒密码", { exact: true });
    const shift = labelBox(w, "位移").locator("input").first();
    await shift.fill("5");
    await sleep(300);
    await labelArea(w, "输入").fill("Hello");
    await button(w, "加密").click();
    await sleep(300);
    const enc = await labelArea(w, "结果").inputValue();
    eq(enc, "Mjqqt", "凯撒位移 5 加密结果");
    await labelArea(w, "输入").fill(enc);
    await button(w, "解密").click();
    await sleep(300);
    eq(await labelArea(w, "结果").inputValue(), "Hello", "凯撒位移 5 解密结果");
    return `Hello →(shift 5)→ ${enc} → Hello`;
  }, { page });

  await H.run("L-22", "古典密码：Atbash 为自反变换", async () => {
    const w = workbench();
    await selectOn(page, labelSelect(w, "算法"), "Atbash", { exact: true });
    await labelArea(w, "输入").fill("Attack At Dawn");
    await button(w, "加密").click();
    await sleep(300);
    const enc = await labelArea(w, "结果").inputValue();
    eq(enc, "Zggzxp Zg Wzdm", "Atbash 加密结果");
    await labelArea(w, "输入").fill(enc);
    await button(w, "加密").click();
    await sleep(300);
    eq(await labelArea(w, "结果").inputValue(), "Attack At Dawn", "Atbash 二次变换应还原");
    return `Attack At Dawn ↔ ${enc}`;
  }, { page });

  await H.shot(page, "L-古典密码");

  /* ---------------- IPv4 / CIDR 计算 ---------------- */

  await H.run("L-23", "IPv4/CIDR：192.168.136.131/24 网段计算", async () => {
    const w = await selectTool(page, "IPv4 / CIDR 计算");
    const input = page.locator('input[placeholder="例如 10.20.30.40/20"]');
    await input.fill("192.168.136.131/24");
    await button(w, "计算网段").click();
    await sleep(500);
    const read = async (label) => {
      const article = w.locator(".network-result-grid article").filter({ hasText: label }).first();
      return ((await article.locator("code").first().textContent()) || "").trim();
    };
    eq(await read("网络地址"), "192.168.136.0/24", "网络地址");
    eq(await read("广播地址"), "192.168.136.255", "广播地址");
    eq(await read("子网掩码"), "255.255.255.0", "子网掩码");
    eq(await read("通配符掩码"), "0.0.0.255", "通配符掩码");
    eq(await read("首个可用地址"), "192.168.136.1", "首个可用地址");
    eq(await read("最后可用地址"), "192.168.136.254", "最后可用地址");
    eq(await read("可用主机数"), "254", "可用主机数");
    eq(await read("地址类型"), "私有地址", "地址类型");
    return "网络=192.168.136.0/24 广播=192.168.136.255 掩码=255.255.255.0 可用主机=254";
  }, { page });

  await H.run("L-24", "IPv4/CIDR：/32 单主机与十六进制/二进制表示", async () => {
    const w = workbench();
    const input = page.locator('input[placeholder="例如 10.20.30.40/20"]');
    await input.fill("10.0.0.7/32");
    await button(w, "计算网段").click();
    await sleep(500);
    const read = async (label) => {
      const article = w.locator(".network-result-grid article").filter({ hasText: label }).first();
      return ((await article.locator("code").first().textContent()) || "").trim();
    };
    eq(await read("网络地址"), "10.0.0.7/32", "/32 网络地址");
    eq(await read("地址总数"), "1", "/32 地址总数");
    eq(await read("可用主机数"), "1", "/32 可用主机数");
    // 10.0.0.7 = 0x0A000007 = 167772167
    eq(await read("整数表示"), "167772167", "整数表示");
    eq(await read("十六进制"), "0x0A000007", "十六进制表示");
    eq(await read("二进制"), "00001010.00000000.00000000.00000111", "二进制表示");
    return "10.0.0.7/32 → 地址总数 1，0x0A000007，00001010.00000000.00000000.00000111";
  }, { page });

  await H.run("L-25", "IPv4/CIDR：非法前缀触发错误提示", async () => {
    const w = workbench();
    const input = page.locator('input[placeholder="例如 10.20.30.40/20"]');
    await clearMessages(page);
    await input.fill("10.0.0.1/33");
    await button(w, "计算网段").click();
    const msg = await lastMessage(page, { timeout: 8000 });
    must(msg && msg.type === "error", `非法前缀应报错，实际 ${msg && msg.type}: ${msg && msg.text}`);
    contains(msg.text, "0 到 32", "错误提示文案");
    await clearMessages(page);
    return `错误提示="${msg.text}"`;
  }, { page });

  await H.shot(page, "L-CIDR计算");

  /* ---------------- HTTP 报文分析 ---------------- */

  const RAW_REQUEST = [
    "POST /api/v1/login?next=/admin HTTP/1.1",
    "Host: target.example.com",
    "User-Agent: Xiezhi-E2E/1.0",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
    "Cookie: JSESSIONID=ABC123",
    "Content-Type: application/json",
    "",
    '{"username":"admin","password":"p@ss"}',
  ].join("\n");

  await H.run("L-26", "HTTP 报文分析：解析原始请求的起始行与报文头", async () => {
    const w = await selectTool(page, "HTTP 报文分析");
    await labelArea(w, "原始 HTTP 报文").fill(RAW_REQUEST);
    await button(w, "解析报文").click();
    await w.locator(".http-summary").first().waitFor({ state: "visible", timeout: 8000 });
    const summary = ((await w.locator(".http-summary").first().textContent()) || "").replace(/\s+/g, " ").trim();
    contains(summary, "HTTP 请求", "报文类型");
    contains(summary, "POST /api/v1/login?next=/admin HTTP/1.1", "起始行");
    contains(summary, "5 个请求/响应头", "报文头数量");

    const headers = await w.locator(".http-header-list > div").allTextContents();
    const flat = headers.map((t) => t.replace(/\s+/g, " ").trim());
    eq(flat.length, 5, "解析出的报文头数量");
    must(flat.some((t) => t.startsWith("Host") && t.includes("target.example.com")), `未解析出 Host 头：${flat.join(" | ")}`);
    must(flat.some((t) => t.startsWith("User-Agent") && t.includes("Xiezhi-E2E/1.0")), `未解析出 User-Agent 头：${flat.join(" | ")}`);
    must(flat.some((t) => t.startsWith("Content-Type") && t.includes("application/json")), `未解析出 Content-Type 头：${flat.join(" | ")}`);

    const body = ((await w.locator(".http-body-preview pre").first().textContent()) || "").trim();
    eq(body, '{"username":"admin","password":"p@ss"}', "正文预览");
    return `方法/路径="POST /api/v1/login?next=/admin HTTP/1.1"，5 个头，正文 ${body.length} 字符`;
  }, { page });

  await H.run("L-27", "HTTP 报文分析：请求中的凭据被标记为注意事项", async () => {
    const w = workbench();
    const checks = (await w.locator(".header-check-list article").allTextContents()).map((t) => t.replace(/\s+/g, " ").trim());
    must(checks.some((t) => t.includes("Authorization") && t.includes("Bearer")), `未提示 Authorization 凭据：${checks.join(" | ")}`);
    must(checks.some((t) => t.includes("Cookie") && t.includes("脱敏")), `未提示 Cookie 脱敏：${checks.join(" | ")}`);
    return `注意事项 ${checks.length} 条：${shorten(checks.join(" / "), 90)}`;
  }, { page });

  await H.run("L-28", "HTTP 报文分析：载入响应示例并给出安全响应头检查", async () => {
    const w = workbench();
    await button(w, "载入响应示例").click();
    await sleep(600);
    const summary = ((await w.locator(".http-summary").first().textContent()) || "").replace(/\s+/g, " ").trim();
    contains(summary, "HTTP 响应", "报文类型");
    contains(summary, "HTTP/1.1 200 OK", "响应起始行");

    const good = await w.locator(".header-check-list article.good").allTextContents();
    const warning = await w.locator(".header-check-list article.warning").allTextContents();
    const flatGood = good.map((t) => t.replace(/\s+/g, " ").trim());
    const flatWarn = warning.map((t) => t.replace(/\s+/g, " ").trim());
    must(flatGood.some((t) => t.includes("X-Content-Type-Options") && t.includes("nosniff")), `X-Content-Type-Options 未判定为通过：${flatGood.join(" | ")}`);
    must(flatWarn.some((t) => t.includes("Content-Security-Policy")), `缺失 CSP 未给出警告：${flatWarn.join(" | ")}`);
    must(flatWarn.some((t) => t.includes("Strict-Transport-Security")), `缺失 HSTS 未给出警告：${flatWarn.join(" | ")}`);
    must(flatWarn.some((t) => t.includes("Cookie session") && t.includes("Secure")), `Set-Cookie 缺少属性未提示：${flatWarn.join(" | ")}`);
    return `通过 ${flatGood.length} 项，警告 ${flatWarn.length} 项（含 CSP/HSTS 缺失与 Cookie 属性缺失）`;
  }, { page });

  await H.shot(page, "L-HTTP报文分析");

  /* ---------------- IOC 指标提取 ---------------- */

  const IOC_TEXT = [
    "2026-08-22 10:11:12 alert: host 203.0.113.45 beaconing to http://evil-c2.test/payload.bin",
    "secondary channel https://cdn.malware-host.test/stage2 ; mail drop: soc@example.com",
    "sample md5 900150983cd24fb0d6963f7d28e17f72 exploiting CVE-2021-44228",
  ].join("\n");

  await H.run("L-29", "IOC 提取：识别 URL/域名/IPv4/邮箱/MD5/CVE 六类指标", async () => {
    const w = await selectTool(page, "IOC 指标提取");
    await labelArea(w, "待分析文本").fill(IOC_TEXT);
    await button(w, "提取 IOC").click();
    await w.locator(".ioc-summary").first().waitFor({ state: "visible", timeout: 8000 });
    await sleep(400);
    const summary = ((await w.locator(".ioc-summary").first().textContent()) || "").replace(/\s+/g, " ").trim();
    const headers = (await w.locator(".ioc-result-grid article header").allTextContents()).map((t) => t.replace(/\s+/g, " ").trim());
    for (const label of ["URL", "域名", "IPv4", "邮箱", "MD5", "CVE"]) {
      must(headers.some((h) => h.startsWith(label)), `未出现 ${label} 分类，实际分类：${headers.join(" | ")}`);
    }
    const count = async (label) => {
      const article = w.locator(".ioc-result-grid article")
        .filter({ has: page.locator("strong", { hasText: new RegExp(`^${escapeRe(label)}$`) }) })
        .first();
      return ((await article.locator("header span").first().textContent()) || "").trim();
    };
    eq(await count("URL"), "2", "URL 数量");
    eq(await count("IPv4"), "1", "IPv4 数量");
    eq(await count("邮箱"), "1", "邮箱数量");
    eq(await count("MD5"), "1", "MD5 数量");
    eq(await count("CVE"), "1", "CVE 数量");
    contains(summary, "6 种类型", "汇总文案");
    return `${summary}（URL 2、IPv4 1、邮箱 1、MD5 1、CVE 1）`;
  }, { page });

  await H.run("L-30", "IOC 提取：结果文本框展示提取到的具体指标值", async () => {
    const w = workbench();
    const area = (label) =>
      w.locator(".ioc-result-grid article")
        .filter({ has: page.locator("strong", { hasText: new RegExp(`^${escapeRe(label)}$`) }) })
        .first()
        .locator("textarea")
        .first();
    const ipv4 = await area("IPv4").inputValue();
    const urls = await area("URL").inputValue();
    const domains = await area("域名").inputValue();
    const cve = await area("CVE").inputValue();
    const email = await area("邮箱").inputValue();
    eq(ipv4.trim(), "203.0.113.45", "IPv4 文本框内容");
    contains(urls, "http://evil-c2.test/payload.bin", "URL 文本框内容");
    contains(urls, "https://cdn.malware-host.test/stage2", "URL 文本框内容");
    contains(domains, "evil-c2.test", "域名文本框内容");
    contains(domains, "cdn.malware-host.test", "域名文本框内容");
    eq(email.trim(), "soc@example.com", "邮箱文本框内容");
    eq(cve.trim(), "CVE-2021-44228", "CVE 文本框内容");
    return `IPv4=${ipv4.trim()}，域名含 evil-c2.test / cdn.malware-host.test，邮箱=${email.trim()}，CVE=${cve.trim()}，URL 两条均已展示`;
  }, { page });

  await H.run("L-31", "IOC 提取：Defang 安全化显示切换", async () => {
    const w = workbench();
    const toggle = button(w, "安全化显示（Defang）");
    await toggle.click();
    await sleep(500);
    const area = w.locator(".ioc-result-grid article")
      .filter({ has: page.locator("strong", { hasText: /^URL$/ }) })
      .first()
      .locator("textarea")
      .first();
    const defanged = await area.inputValue();
    contains(defanged, "hxxp://evil-c2[.]test/payload[.]bin", "Defang 后的 URL");
    must(!defanged.includes("http://evil-c2.test"), `Defang 后不应残留可点击 URL：${shorten(defanged, 120)}`);
    const backLabel = ((await button(w, "显示原始格式").textContent()) || "").trim();
    eq(backLabel, "显示原始格式", "切换后的按钮文案");
    await button(w, "显示原始格式").click();
    await sleep(400);
    contains(await area.inputValue(), "http://evil-c2.test/payload.bin", "还原后的 URL");
    return `Defang: ${shorten(defanged.split("\n")[0], 60)}`;
  }, { page });

  await H.shot(page, "L-IOC提取");

  /* ---------------- URL / 接口提取 ---------------- */

  const ENDPOINT_SOURCE = [
    '<script src="https://cdn.example.org/lib/app.min.js"></script>',
    '<a href="/api/v1/users">users</a>',
    'fetch("/api/v1/orders?page=1").then(r => r.json());',
    "const doc = 'https://docs.example.net/guide';",
  ].join("\n");

  await H.run("L-32", "端点提取：从 HTML/JS 中提取绝对 URL、相对路径与域名", async () => {
    const w = await selectTool(page, "URL / 接口提取");
    await labelArea(w, "HTML / JavaScript / 日志文本").fill(ENDPOINT_SOURCE);
    await button(w, "提取端点").click();
    await w.locator(".endpoint-results").first().waitFor({ state: "visible", timeout: 8000 });
    await sleep(400);
    const block = (label) =>
      w.locator(".endpoint-results article")
        .filter({ has: page.locator("strong", { hasText: new RegExp(`^${escapeRe(label)}$`) }) })
        .first();
    const urls = await block("完整 URL").locator("textarea").first().inputValue();
    const paths = await block("相对路径").locator("textarea").first().inputValue();
    const domains = await block("关联域名").locator("textarea").first().inputValue();
    contains(urls, "https://cdn.example.org/lib/app.min.js", "绝对 URL");
    contains(urls, "https://docs.example.net/guide", "绝对 URL");
    contains(paths, "/api/v1/users", "相对路径");
    contains(paths, "/api/v1/orders?page=1", "相对路径");
    contains(domains, "cdn.example.org", "关联域名");
    contains(domains, "docs.example.net", "关联域名");
    eq(((await block("相对路径").locator("header span").first().textContent()) || "").trim(), "2", "相对路径数量");
    return `URL 2 条、相对路径 2 条、域名 2 个`;
  }, { page });

  await H.run("L-33", "端点提取：填写基础 URL 后相对路径被补全为绝对地址", async () => {
    const w = workbench();
    await labelInput(w, "基础 URL（可选）").fill("https://target.example.com/app/");
    await button(w, "提取端点").click();
    await sleep(600);
    const block = (label) =>
      w.locator(".endpoint-results article")
        .filter({ has: page.locator("strong", { hasText: new RegExp(`^${escapeRe(label)}$`) }) })
        .first();
    const urls = await block("完整 URL").locator("textarea").first().inputValue();
    contains(urls, "https://target.example.com/api/v1/users", "补全后的绝对 URL");
    contains(urls, "https://target.example.com/api/v1/orders?page=1", "补全后的绝对 URL");
    const domains = await block("关联域名").locator("textarea").first().inputValue();
    contains(domains, "target.example.com", "补全后新增的域名");
    return "相对路径已按基础 URL 补全为 https://target.example.com/api/v1/*";
  }, { page });

  await H.shot(page, "L-端点提取");

  /* ---------------- 文件哈希与类型 ---------------- */

  await H.run("L-34", "文件哈希：选择文本文件计算 MD5/SHA 摘要与大小", async () => {
    const w = await selectTool(page, "文件哈希与类型");
    await w.locator(".file-drop input[type=file]").first().setInputFiles(fixtures.textFile);
    await w.locator(".file-meta-grid").first().waitFor({ state: "visible", timeout: 20000 });
    await sleep(400);
    const meta = async (label) => {
      const article = w.locator(".file-meta-grid article").filter({ hasText: label }).first();
      return ((await article.locator("strong, code").first().textContent()) || "").trim();
    };
    eq(await meta("文件名"), path.basename(fixtures.textFile), "文件名");
    eq(await meta("文件大小"), `${fixtures.textBuf.length} B`, "文件大小");
    const read = async (name) => {
      const card = w.locator(".file-hash-results article")
        .filter({ has: page.locator("strong", { hasText: new RegExp(`^${escapeRe(name)}$`) }) })
        .first();
      return ((await card.locator("code").first().textContent()) || "").trim();
    };
    eq(await read("MD5"), fixtures.textHashes.MD5, "文件 MD5");
    eq(await read("SHA-1"), fixtures.textHashes["SHA-1"], "文件 SHA-1");
    eq(await read("SHA-256"), fixtures.textHashes["SHA-256"], "文件 SHA-256");
    eq(await read("SHA-512"), fixtures.textHashes["SHA-512"], "文件 SHA-512");
    return `${path.basename(fixtures.textFile)} ${fixtures.textBuf.length}B，SHA-256=${fixtures.textHashes["SHA-256"].slice(0, 24)}…（四种摘要全部匹配）`;
  }, { page });

  await H.run("L-35", "文件哈希：魔数识别 PNG 并展示文件头 16 字节与信息熵", async () => {
    const w = workbench();
    await w.locator(".file-drop input[type=file]").first().setInputFiles(fixtures.pngFile);
    await sleep(1500);
    const meta = async (label) => {
      const article = w.locator(".file-meta-grid article").filter({ hasText: label }).first();
      return ((await article.locator("strong, code").first().textContent()) || "").trim();
    };
    eq(await meta("文件名"), path.basename(fixtures.pngFile), "文件名");
    eq(await meta("魔数推断"), "PNG 图片", "魔数推断结果");
    eq(await meta("文件头 16 字节"), fixtures.pngBuf.subarray(0, 16).toString("hex").toUpperCase(), "文件头 16 字节");
    const entropy = await meta("信息熵");
    const value = Number.parseFloat(entropy);
    must(Number.isFinite(value) && value > 0 && value <= 8, `信息熵应在 (0,8] 区间，实际 "${entropy}"`);
    return `魔数推断=PNG 图片，文件头=${fixtures.pngBuf.subarray(0, 8).toString("hex").toUpperCase()}…，信息熵=${entropy}`;
  }, { page });

  await H.shot(page, "L-文件哈希");

  /* ---------------- 文件十六进制查看 ---------------- */

  await H.run("L-36", "十六进制查看：载入文件后渲染 Offset/Hex/ASCII 对照表", async () => {
    const w = await selectTool(page, "文件十六进制查看");
    await w.locator(".file-drop input[type=file]").first().setInputFiles(fixtures.hexFile);
    await w.locator(".hex-viewer-table tbody tr").first().waitFor({ state: "visible", timeout: 20000 });
    await sleep(400);
    const rows = await w.locator(".hex-viewer-table tbody tr").count();
    eq(rows, 32, "首页行数（512 字节 / 每行 16 字节）");
    const firstRow = w.locator(".hex-viewer-table tbody tr").first();
    eq(((await firstRow.locator("th").first().textContent()) || "").trim(), "00000000", "首行偏移标签");
    eq(((await firstRow.locator("td.hex-viewer-ascii").first().textContent()) || ""), "XIEZHI-HEX-0000 ", "首行 ASCII");
    const cells = await firstRow.locator("td.hex-viewer-hex-cells span").allTextContents();
    eq(cells.length, 16, "首行十六进制单元格数量");
    eq(cells[0], "58", "首字节十六进制（'X'）");
    const fileBar = ((await w.locator(".hex-viewer-filebar").first().textContent()) || "").replace(/\s+/g, " ").trim();
    contains(fileBar, path.basename(fixtures.hexFile), "文件名展示");
    contains(fileBar, `${(fixtures.hexBuf.length / 1024).toFixed(2)} KB`, "文件大小展示");
    const range = ((await w.locator(".hex-viewer-range").first().textContent()) || "").replace(/\s+/g, " ").trim();
    eq(range, "0x00000000 – 0x000001FF", "首页偏移区间");
    return `32 行 × 16 字节，首行 ASCII="XIEZHI-HEX-0000 "，区间 ${range}`;
  }, { page });

  await H.run("L-37", "十六进制查看：下一页/上一页按分块翻页", async () => {
    const w = workbench();
    const prev = button(w, "上一页");
    must(await prev.isDisabled(), "首页时「上一页」应处于禁用状态");
    await button(w, "下一页").click();
    await sleep(900);
    const range = ((await w.locator(".hex-viewer-range").first().textContent()) || "").replace(/\s+/g, " ").trim();
    eq(range, "0x00000200 – 0x000003FF", "第二页偏移区间");
    const ascii = (await w.locator(".hex-viewer-table tbody tr").first().locator("td.hex-viewer-ascii").first().textContent()) || "";
    eq(ascii, "XIEZHI-HEX-0032 ", "第二页首行 ASCII");
    must(!(await prev.isDisabled()), "翻页后「上一页」应可用");
    await prev.click();
    await sleep(900);
    const back = ((await w.locator(".hex-viewer-range").first().textContent()) || "").replace(/\s+/g, " ").trim();
    eq(back, "0x00000000 – 0x000001FF", "返回首页后的偏移区间");
    return `下一页→${range}（首行 ASCII=XIEZHI-HEX-0032 ），上一页→${back}`;
  }, { page });

  await H.run("L-38", "十六进制查看：跳转到指定偏移 0x100", async () => {
    const w = workbench();
    const offset = page.locator("#hex-viewer-offset");
    await offset.fill("0x100");
    await button(w, "跳转").click();
    await sleep(900);
    const range = ((await w.locator(".hex-viewer-range").first().textContent()) || "").replace(/\s+/g, " ").trim();
    eq(range, "0x00000100 – 0x000002FF", "跳转后的偏移区间");
    const firstRow = w.locator(".hex-viewer-table tbody tr").first();
    eq(((await firstRow.locator("th").first().textContent()) || "").trim(), "00000100", "跳转后首行偏移标签");
    // 0x100 = 256 字节 = 第 16 行（每行 16 字节，行内容自描述）
    eq(((await firstRow.locator("td.hex-viewer-ascii").first().textContent()) || ""), "XIEZHI-HEX-0016 ", "跳转后首行 ASCII");
    return `跳转 0x100 → ${range}，首行 ASCII="XIEZHI-HEX-0016 "`;
  }, { page });

  await H.run("L-39", "十六进制查看：非法偏移量给出错误提示", async () => {
    const w = workbench();
    await clearMessages(page);
    await page.locator("#hex-viewer-offset").fill("not-an-offset");
    await button(w, "跳转").click();
    const msg = await lastMessage(page, { timeout: 8000 });
    must(msg && msg.type === "error", `非法偏移量应报错，实际 ${msg && msg.type}: ${msg && msg.text}`);
    contains(msg.text, "偏移量", "错误提示文案");
    await clearMessages(page);
    return `错误提示="${msg.text}"`;
  }, { page });

  await H.shot(page, "L-十六进制查看");

  /* ---------------- JWT 解析 ---------------- */

  await H.run("L-40", "JWT 解析：解码 Header 与 Payload 声明", async () => {
    const w = await selectTool(page, "JWT 解析");
    await labelArea(w, "JWT").fill(JWT_TOKEN);
    await button(w, "解析").click();
    await sleep(500);
    const header = JSON.parse(await labelArea(w, "Header").inputValue());
    const payload = JSON.parse(await labelArea(w, "Payload").inputValue());
    eq(header.alg, "HS256", "JWT header.alg");
    eq(header.typ, "JWT", "JWT header.typ");
    eq(payload.sub, "1234567890", "JWT payload.sub");
    eq(payload.name, "John Doe", "JWT payload.name");
    eq(payload.iat, 1516239022, "JWT payload.iat");
    return `alg=${header.alg} typ=${header.typ}；sub=${payload.sub} name=${payload.name} iat=${payload.iat}`;
  }, { page });

  await H.run("L-41", "JWT 解析：非法令牌给出错误提示", async () => {
    const w = workbench();
    await clearMessages(page);
    await labelArea(w, "JWT").fill("not-a-jwt-token");
    await button(w, "解析").click();
    const msg = await lastMessage(page, { timeout: 8000 });
    must(msg && msg.type === "error", `非法 JWT 应报错，实际 ${msg && msg.type}: ${msg && msg.text}`);
    contains(msg.text, "JWT", "错误提示文案");
    await clearMessages(page);
    return `错误提示="${msg.text}"`;
  }, { page });

  await H.shot(page, "L-JWT解析");

  /* ---------------- JSON 工具 ---------------- */

  const JSON_RAW = '{"b":2,"a":{"d":4,"c":3},"z":[3,1,2]}';

  await H.run("L-42", "JSON 工具：按 2 空格缩进格式化", async () => {
    const w = await selectTool(page, "JSON 工具");
    await selectOn(page, labelSelect(w, "缩进"), "2 空格", { exact: true });
    await labelArea(w, "JSON 输入").fill(JSON_RAW);
    await button(w, "格式化").click();
    await sleep(400);
    const out = await labelArea(w, "结果").inputValue();
    eq(out, JSON.stringify(JSON.parse(JSON_RAW), null, 2), "2 空格格式化结果");
    must(out.includes('\n  "b": 2'), `应出现 2 空格缩进，实际首行：${shorten(out, 80)}`);
    return `格式化为 ${out.split("\n").length} 行，2 空格缩进`;
  }, { page });

  await H.run("L-43", "JSON 工具：切换 4 空格缩进后重新格式化", async () => {
    const w = workbench();
    await selectOn(page, labelSelect(w, "缩进"), "4 空格", { exact: true });
    await button(w, "格式化").click();
    await sleep(400);
    const out = await labelArea(w, "结果").inputValue();
    eq(out, JSON.stringify(JSON.parse(JSON_RAW), null, 4), "4 空格格式化结果");
    must(out.includes('\n    "b": 2'), `应出现 4 空格缩进，实际：${shorten(out, 80)}`);
    return "缩进切换为 4 空格后输出同步变化";
  }, { page });

  await H.run("L-44", "JSON 工具：压缩为单行", async () => {
    const w = workbench();
    await button(w, "压缩").click();
    await sleep(400);
    const out = await labelArea(w, "结果").inputValue();
    eq(out, JSON_RAW, "压缩结果");
    eq(out.includes("\n"), false, "压缩结果不应含换行");
    return `压缩结果=${out}`;
  }, { page });

  await H.run("L-45", "JSON 工具：递归排序键名", async () => {
    const w = workbench();
    await button(w, "排序键名").click();
    await sleep(400);
    const out = await labelArea(w, "结果").inputValue();
    const parsed = JSON.parse(out);
    eq(Object.keys(parsed).join(","), "a,b,z", "顶层键顺序");
    eq(Object.keys(parsed.a).join(","), "c,d", "嵌套对象键顺序");
    eq(JSON.stringify(parsed.z), "[3,1,2]", "数组元素顺序不应被改变");
    must(out !== JSON_RAW, "排序结果应与原始输入不同");
    await clearMessages(page);
    await button(w, "复制结果").click();
    const msg = await lastMessage(page, { timeout: 8000 });
    must(msg && msg.type === "success", `复制结果未出现成功提示，实际 ${msg && msg.type}: ${msg && msg.text}`);
    await clearMessages(page);
    return `顶层 a,b,z；嵌套 c,d；数组顺序保持 [3,1,2]；复制提示="${msg.text}"`;
  }, { page });

  await H.shot(page, "L-JSON工具");

  /* ---------------- 时间戳转换 ---------------- */

  await H.run("L-46", "时间戳转换：秒级时间戳 → 日期", async () => {
    const w = await selectTool(page, "时间戳转换");
    const article = w.locator(".timestamp-tools > article").nth(0);
    await article.locator("input").first().fill("1700000000");
    await article.locator("button").first().click();
    await sleep(400);
    const out = ((await article.locator("pre").first().textContent()) || "").trim();
    contains(out, "标准时间：2023-11-14T22:13:20.000Z", "秒级时间戳转换结果");
    must(/\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(out), `未输出本地时间，实际 "${shorten(out, 120)}"`);
    return `1700000000 → ${shorten(out, 80)}`;
  }, { page });

  await H.run("L-47", "时间戳转换：毫秒级时间戳自动识别", async () => {
    const w = workbench();
    const article = w.locator(".timestamp-tools > article").nth(0);
    await article.locator("input").first().fill("1700000000000");
    await article.locator("button").first().click();
    await sleep(400);
    const out = ((await article.locator("pre").first().textContent()) || "").trim();
    contains(out, "标准时间：2023-11-14T22:13:20.000Z", "毫秒级时间戳转换结果");
    return `1700000000000 与 1700000000 转换到同一时刻`;
  }, { page });

  await H.run("L-48", "时间戳转换：日期 → 秒/毫秒时间戳", async () => {
    const w = workbench();
    const article = w.locator(".timestamp-tools > article").nth(1);
    await article.locator("input").first().fill("2023-11-14T22:13:20Z");
    await article.locator("button").first().click();
    await sleep(400);
    const out = ((await article.locator("pre").first().textContent()) || "").replace(/\s+/g, " ").trim();
    contains(out, "秒：1700000000", "秒级结果");
    contains(out, "毫秒：1700000000000", "毫秒级结果");
    return `2023-11-14T22:13:20Z → ${out}`;
  }, { page });

  await H.shot(page, "L-时间戳转换");

  /* ---------------- 文本处理 ---------------- */

  await H.run("L-49", "文本处理：实时统计字符/字节/单词/行数", async () => {
    const w = await selectTool(page, "文本处理");
    await labelArea(w, "输入").fill("Hello 世界\nsecond line");
    await sleep(400);
    const stats = (await w.locator(".text-stats span").allTextContents()).map((t) => t.replace(/\s+/g, " ").trim());
    const chars = Array.from("Hello 世界\nsecond line").length;
    const bytes = Buffer.byteLength("Hello 世界\nsecond line", "utf8");
    eq(stats[0], `字符 ${chars}`, "字符数");
    eq(stats[1], `字节 ${bytes}`, "字节数");
    eq(stats[2], "单词 4", "单词数");
    eq(stats[3], "行数 2", "行数");
    return `${stats.join(" / ")}`;
  }, { page });

  await H.run("L-50", "文本处理：转大写与转小写", async () => {
    const w = workbench();
    await labelArea(w, "输入").fill("Hello Xiezhi");
    await selectOn(page, labelSelect(w, "处理方式"), "转大写", { exact: true });
    await button(w, "处理文本").click();
    await sleep(350);
    eq(await labelArea(w, "结果").inputValue(), "HELLO XIEZHI", "转大写结果");
    await selectOn(page, labelSelect(w, "处理方式"), "转小写", { exact: true });
    await button(w, "处理文本").click();
    await sleep(350);
    eq(await labelArea(w, "结果").inputValue(), "hello xiezhi", "转小写结果");
    return "Hello Xiezhi → HELLO XIEZHI / hello xiezhi";
  }, { page });

  await H.run("L-51", "文本处理：行去重与行排序", async () => {
    const w = workbench();
    await labelArea(w, "输入").fill("beta\nalpha\nbeta\ngamma\nalpha");
    await selectOn(page, labelSelect(w, "处理方式"), "行去重", { exact: true });
    await button(w, "处理文本").click();
    await sleep(350);
    eq(await labelArea(w, "结果").inputValue(), "beta\nalpha\ngamma", "行去重结果");
    await selectOn(page, labelSelect(w, "处理方式"), "行排序", { exact: true });
    await button(w, "处理文本").click();
    await sleep(350);
    eq(await labelArea(w, "结果").inputValue(), "alpha\nalpha\nbeta\nbeta\ngamma", "行排序结果");
    return "5 行去重为 3 行；排序后 alpha,alpha,beta,beta,gamma";
  }, { page });

  await H.run("L-52", "文本处理：反转文本", async () => {
    const w = workbench();
    await labelArea(w, "输入").fill("Xiezhi 獬豸");
    await selectOn(page, labelSelect(w, "处理方式"), "反转文本", { exact: true });
    await button(w, "处理文本").click();
    await sleep(350);
    eq(await labelArea(w, "结果").inputValue(), Array.from("Xiezhi 獬豸").reverse().join(""), "反转结果");
    return `Xiezhi 獬豸 → ${Array.from("Xiezhi 獬豸").reverse().join("")}`;
  }, { page });

  await H.run("L-53", "文本处理：snake_case / kebab-case / camelCase 命名转换", async () => {
    const w = workbench();
    await labelArea(w, "输入").fill("Offline Tool Box");
    await selectOn(page, labelSelect(w, "处理方式"), "snake_case", { exact: true });
    await button(w, "处理文本").click();
    await sleep(350);
    eq(await labelArea(w, "结果").inputValue(), "offline_tool_box", "snake_case 结果");
    await selectOn(page, labelSelect(w, "处理方式"), "kebab-case", { exact: true });
    await button(w, "处理文本").click();
    await sleep(350);
    eq(await labelArea(w, "结果").inputValue(), "offline-tool-box", "kebab-case 结果");
    await selectOn(page, labelSelect(w, "处理方式"), "camelCase", { exact: true });
    await button(w, "处理文本").click();
    await sleep(350);
    eq(await labelArea(w, "结果").inputValue(), "offlineToolBox", "camelCase 结果");
    return "Offline Tool Box → offline_tool_box / offline-tool-box / offlineToolBox";
  }, { page });

  await H.shot(page, "L-文本处理");

  /* ---------------- 安全随机生成 ---------------- */

  await H.run("L-54", "随机生成：按设定长度生成密码", async () => {
    const w = await selectTool(page, "安全随机生成");
    const length = labelBox(w, "长度").locator("input").first();
    await length.fill("40");
    await sleep(300);
    await button(w, "生成密码").click();
    await sleep(400);
    const first = await labelArea(w, "生成结果").inputValue();
    eq(first.length, 40, "生成密码长度");
    await button(w, "生成密码").click();
    await sleep(400);
    const second = await labelArea(w, "生成结果").inputValue();
    eq(second.length, 40, "第二次生成密码长度");
    must(first !== second, "两次生成的随机密码不应相同");
    return `长度=40，两次结果不同（示例 ${shorten(first, 40)}）`;
  }, { page });

  await H.run("L-55", "随机生成：字符集勾选影响生成结果", async () => {
    const w = workbench();
    await setCheckbox(w, "大写字母", false);
    await setCheckbox(w, "数字", false);
    await setCheckbox(w, "符号", false);
    await setCheckbox(w, "小写字母", true);
    await button(w, "生成密码").click();
    await sleep(400);
    const out = await labelArea(w, "生成结果").inputValue();
    must(/^[a-z]{40}$/.test(out), `仅勾选小写字母时应只含 a-z，实际 "${out}"`);
    return `仅小写字符集 → ${shorten(out, 45)}`;
  }, { page });

  await H.run("L-56", "随机生成：全部取消字符集时给出错误提示", async () => {
    const w = workbench();
    await setCheckbox(w, "小写字母", false);
    await clearMessages(page);
    await button(w, "生成密码").click();
    const msg = await lastMessage(page, { timeout: 8000 });
    must(msg && msg.type === "error", `未选字符集时应报错，实际 ${msg && msg.type}: ${msg && msg.text}`);
    contains(msg.text, "至少选择一种", "错误提示文案");
    await clearMessages(page);
    for (const name of ["大写字母", "小写字母", "数字", "符号"]) await setCheckbox(w, name, true);
    return `错误提示="${msg.text}"`;
  }, { page });

  await H.run("L-57", "随机生成：生成符合 RFC 4122 的 UUID", async () => {
    const w = workbench();
    await button(w, "生成 UUID").click();
    await sleep(400);
    const uuid = await labelArea(w, "生成结果").inputValue();
    must(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid),
      `UUID 格式不符合 v4 规范，实际 "${uuid}"`,
    );
    return `UUID=${uuid}`;
  }, { page });

  await H.run("L-58", "随机生成：生成指定字节数的 Base64 随机串", async () => {
    const w = workbench();
    const length = labelBox(w, "长度").locator("input").first();
    await length.fill("32");
    await sleep(300);
    await button(w, "生成随机字节（Base64）").click();
    await sleep(400);
    const out = await labelArea(w, "生成结果").inputValue();
    must(/^[A-Za-z0-9+/]+=*$/.test(out), `随机字节应为标准 Base64，实际 "${out}"`);
    eq(Buffer.from(out, "base64").length, 32, "Base64 解码后的字节数");
    return `Base64=${out}（解码为 32 字节）`;
  }, { page });

  await H.shot(page, "L-随机生成");

  /* ---------------- URL / 参数解析 ---------------- */

  await H.run("L-59", "URL 解析：拆解协议、主机、端口、路径与查询参数", async () => {
    const w = await selectTool(page, "URL / 参数解析");
    const pane = page.locator(".url-tool-tabs .el-tab-pane:visible").first();
    await labelArea(pane, "URL").fill("https://user@target.example.com:8443/admin/panel?id=7&debug=true#frag");
    await button(pane, "解析 URL").click();
    await sleep(500);
    const parsed = JSON.parse(await labelArea(pane, "解析结果").inputValue());
    eq(parsed.protocol, "https", "protocol");
    eq(parsed.host, "target.example.com:8443", "host");
    eq(parsed.hostname, "target.example.com", "hostname");
    eq(parsed.port, "8443", "port");
    eq(parsed.username, "user", "username");
    eq(parsed.pathname, "/admin/panel", "pathname");
    eq(parsed.search, "?id=7&debug=true", "search");
    eq(parsed.hash, "#frag", "hash");
    eq(JSON.stringify(parsed.query), '{"id":["7"],"debug":["true"]}', "query 参数");
    return `protocol=https host=target.example.com:8443 path=/admin/panel query={id:7,debug:true}`;
  }, { page });

  await H.run("L-60", "URL 构造：由协议/主机/路径/查询串拼出完整地址", async () => {
    await page.locator(".url-tool-tabs .el-tabs__item").filter({ hasText: "URL 构造" }).first().click();
    await sleep(500);
    const pane = page.locator(".url-tool-tabs .el-tab-pane:visible").first();
    await labelInput(pane, "协议").fill("http");
    await labelInput(pane, "主机").fill("10.0.0.5:8080");
    await labelInput(pane, "路径").fill("/api/v2/login");
    await labelInput(pane, "查询串（不含 ?）").fill("next=/dashboard&lang=zh");
    await button(pane, "构造 URL").click();
    await sleep(400);
    const built = await labelArea(pane, "构造结果").inputValue();
    const core = "http://10.0.0.5:8080/api/v2/login?next=/dashboard&lang=zh";
    must(built.startsWith(core), `构造结果应以 "${core}" 开头，实际 "${built}"`);
    // 「URL 构造」页只有协议/主机/路径/查询串四个输入框，没有 fragment 输入框，
    // 而 buildUrl 仍会拼接由「URL 解析」页写入的 urlHash（此处为 #frag）。
    // 这是与上一个用例共享状态的既有行为，此处固化断言以便回归时察觉变化。
    eq(built, `${core}#frag`, "构造结果（含由解析页带入的 fragment）");
    return `构造结果=${built}（末尾 #frag 由「URL 解析」页带入，构造页无 fragment 输入框可清除）`;
  }, { page });

  await H.run("L-61", "Query 参数：解析为键值行并重新拼接", async () => {
    await page.locator(".url-tool-tabs .el-tabs__item").filter({ hasText: "Query 参数" }).first().click();
    await sleep(500);
    const pane = page.locator(".url-tool-tabs .el-tab-pane:visible").first();
    await labelArea(pane, "Query 字符串").fill("id=1&name=test&redirect=/admin");
    await button(pane, "解析参数").click();
    await sleep(500);
    const rows = pane.locator(".query-parameter-list .offline-control-row");
    eq(await rows.count(), 3, "解析出的参数行数");
    eq(await rows.nth(0).locator("input").nth(0).inputValue(), "id", "第 1 行 key");
    eq(await rows.nth(2).locator("input").nth(0).inputValue(), "redirect", "第 3 行 key");
    eq(await rows.nth(2).locator("input").nth(1).inputValue(), "/admin", "第 3 行 value");

    await button(pane, "重新拼接").click();
    await sleep(400);
    eq(await labelArea(pane, "拼接结果").inputValue(), "id=1&name=test&redirect=%2Fadmin", "重新拼接结果");
    return "解析出 3 行参数，重新拼接为 id=1&name=test&redirect=%2Fadmin";
  }, { page });

  await H.run("L-62", "Query 参数：新增参数行后拼接结果同步更新", async () => {
    const pane = page.locator(".url-tool-tabs .el-tab-pane:visible").first();
    await button(pane, "新增参数行").click();
    await sleep(400);
    const rows = pane.locator(".query-parameter-list .offline-control-row");
    eq(await rows.count(), 4, "新增后的参数行数");
    await rows.nth(3).locator("input").nth(0).fill("debug");
    await rows.nth(3).locator("input").nth(1).fill("true");
    await button(pane, "重新拼接").click();
    await sleep(400);
    eq(
      await labelArea(pane, "拼接结果").inputValue(),
      "id=1&name=test&redirect=%2Fadmin&debug=true",
      "新增参数后的拼接结果",
    );
    return "新增 debug=true 后拼接结果=id=1&name=test&redirect=%2Fadmin&debug=true";
  }, { page });

  await H.shot(page, "L-URL参数解析");

  /* ---------------- 哈希类型识别 ---------------- */

  await H.run("L-63", "哈希识别：32 位十六进制识别为 MD5 / NTLM", async () => {
    const w = await selectTool(page, "哈希类型识别");
    await labelArea(w, "哈希 / 密文").fill(EXPECT.md5abc);
    await button(w, "识别类型").click();
    await sleep(500);
    const names = (await w.locator(".pentest-hit-list .pentest-hit-card header strong").allTextContents()).map((t) => t.trim());
    eq(names.join(","), "MD5,NTLM", "识别结果");
    const first = w.locator(".pentest-hit-list .pentest-hit-card").first();
    eq(((await first.locator("header span").first().textContent()) || "").trim(), "medium", "MD5 置信度");
    return `${EXPECT.md5abc} → ${names.join(" / ")}`;
  }, { page });

  await H.run("L-64", "哈希识别：64 位十六进制与 bcrypt 前缀", async () => {
    const w = workbench();
    await labelArea(w, "哈希 / 密文").fill(EXPECT.sha256abc);
    await button(w, "识别类型").click();
    await sleep(500);
    let names = (await w.locator(".pentest-hit-list .pentest-hit-card header strong").allTextContents()).map((t) => t.trim());
    must(names.includes("SHA-256"), `64 位 hex 应识别为 SHA-256，实际 ${names.join(",")}`);

    await labelArea(w, "哈希 / 密文").fill("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");
    await button(w, "识别类型").click();
    await sleep(500);
    names = (await w.locator(".pentest-hit-list .pentest-hit-card header strong").allTextContents()).map((t) => t.trim());
    eq(names[0], "bcrypt", "bcrypt 识别结果");
    eq(((await w.locator(".pentest-hit-list .pentest-hit-card header span").first().textContent()) || "").trim(), "high", "bcrypt 置信度");
    return "64 位 hex → SHA-256；$2a$10$… → bcrypt(high)";
  }, { page });

  await H.run("L-65", "哈希识别：未匹配规则时返回 Unknown", async () => {
    const w = workbench();
    await labelArea(w, "哈希 / 密文").fill("zzz-not-a-hash-123");
    await button(w, "识别类型").click();
    await sleep(500);
    const names = (await w.locator(".pentest-hit-list .pentest-hit-card header strong").allTextContents()).map((t) => t.trim());
    eq(names.join(","), "Unknown", "未知输入的识别结果");
    return "无法匹配时返回 Unknown";
  }, { page });

  await H.shot(page, "L-哈希识别");

  /* ---------------- Payload 编码链 ---------------- */

  await H.run("L-66", "Payload 编码链：预设 XSS + URL→Base64 两步编码", async () => {
    const w = await selectTool(page, "Payload 编码链");
    await w.locator(".payload-presets button").filter({ hasText: "XSS 基础" }).first().click();
    await sleep(600);
    const final = await labelArea(w, "最终输出").inputValue();
    eq(final, XSS_URL_BASE64, "编码链最终输出");
    const traces = await w.locator(".pentest-hit-list .pentest-hit-card").count();
    eq(traces, 2, "编码链步骤数");
    const step1 = ((await w.locator(".pentest-hit-list .pentest-hit-card").nth(0).locator("pre").first().textContent()) || "").trim();
    const step2 = ((await w.locator(".pentest-hit-list .pentest-hit-card").nth(1).locator("pre").first().textContent()) || "").trim();
    eq(step1, XSS_URL_ENCODED, "第 1 步 URL 编码输出");
    eq(step2, XSS_URL_BASE64, "第 2 步 Base64 编码输出");
    const headers = (await w.locator(".pentest-hit-list .pentest-hit-card header strong").allTextContents()).map((t) => t.replace(/\s+/g, " ").trim());
    eq(headers[0], "步骤 1 · url", "第 1 步标签");
    eq(headers[1], "步骤 2 · base64", "第 2 步标签");
    return `编码链结果=${final}`;
  }, { page });

  await H.run("L-67", "Payload 编码链：调整为单步 URL 编码后结果变化", async () => {
    const w = workbench();
    await toggleMultiOptions(page, w.locator(".payload-chain-field .el-select").first(), ["Base64"]);
    await button(w, "执行编码链").click();
    await sleep(500);
    const final = await labelArea(w, "最终输出").inputValue();
    eq(final, XSS_URL_ENCODED, "单步 URL 编码结果");
    eq(await w.locator(".pentest-hit-list .pentest-hit-card").count(), 1, "编码链步骤数");
    return `去掉 Base64 后结果=${final}`;
  }, { page });

  await H.run("L-68", "Payload 编码链：追加 HTML 实体与 Hex 组成三步链", async () => {
    const w = workbench();
    await toggleMultiOptions(page, w.locator(".payload-chain-field .el-select").first(), ["HTML 实体", "Hex"]);
    await labelArea(w, "原始 Payload").fill("' OR '1'='1");
    await button(w, "执行编码链").click();
    await sleep(500);
    const expectedUrl = encodeURIComponent("' OR '1'='1");
    const expectedHtml = expectedUrl.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    const expectedHex = Buffer.from(expectedHtml, "utf8").toString("hex");
    const final = await labelArea(w, "最终输出").inputValue();
    eq(await w.locator(".pentest-hit-list .pentest-hit-card").count(), 3, "编码链步骤数");
    eq(final, expectedHex, "三步编码链最终输出");
    return `url→html→hex 结果=${shorten(final, 60)}`;
  }, { page });

  await H.shot(page, "L-Payload编码链");

  /* ---------------- 正则提取实验室 ---------------- */

  await H.run("L-69", "正则实验室：提取匹配项与捕获组", async () => {
    const w = await selectTool(page, "正则提取实验室");
    await labelInput(w, "正则").fill("([a-z]+)@([a-z.]+)");
    await labelInput(w, "标志").fill("gi");
    await labelArea(w, "输入文本").fill("alice@example.com 和 bob@test.org 都在通讯录中");
    await clearMessages(page);
    await button(w, "提取匹配").click();
    await sleep(500);
    const out = await labelArea(w, "匹配结果").inputValue();
    contains(out, "#1 @0", "第 1 处匹配位置");
    contains(out, "alice@example.com", "第 1 处匹配文本");
    contains(out, 'groups: ["alice","example.com"]', "第 1 处捕获组");
    contains(out, "#2", "第 2 处匹配");
    contains(out, "bob@test.org", "第 2 处匹配文本");
    contains(out, 'groups: ["bob","test.org"]', "第 2 处捕获组");
    const msg = await lastMessage(page, { timeout: 6000 });
    must(msg && msg.text.includes("匹配 2 处"), `提示应为「匹配 2 处」，实际 ${msg && msg.text}`);
    await clearMessages(page);
    return `匹配 2 处，捕获组 ["alice","example.com"] / ["bob","test.org"]`;
  }, { page });

  await H.run("L-70", "正则实验室：无匹配与非法表达式的处理", async () => {
    const w = workbench();
    await labelInput(w, "正则").fill("NOT-PRESENT-\\d+");
    await button(w, "提取匹配").click();
    await sleep(500);
    eq(await labelArea(w, "匹配结果").inputValue(), "无匹配", "无匹配时的输出");

    await clearMessages(page);
    await labelInput(w, "正则").fill("([a-z");
    await button(w, "提取匹配").click();
    const msg = await lastMessage(page, { timeout: 8000 });
    must(msg && msg.type === "error", `非法正则应报错，实际 ${msg && msg.type}: ${msg && msg.text}`);
    contains(msg.text, "正则表达式无效", "错误提示文案");
    await clearMessages(page);
    return `无匹配→"无匹配"；非法表达式提示="${msg.text}"`;
  }, { page });

  await H.shot(page, "L-正则实验室");

  /* ---------------- 进制 / Unicode 转换 ---------------- */

  await H.run("L-71", "进制转换：文本 → Hex 与 Unicode 码点", async () => {
    const w = await selectTool(page, "进制 / Unicode 转换");
    await selectOn(page, labelSelect(w, "编码方式"), "Hex", { exact: true });
    await labelArea(w, "文本").fill("Xiezhi");
    await button(w, "文本 → 编码").click();
    await sleep(400);
    const hex = await labelArea(w, "编码结果").inputValue();
    eq(hex, "58 69 65 7a 68 69", "Hex 编码结果");

    await selectOn(page, labelSelect(w, "编码方式"), "Unicode 码点", { exact: true });
    await button(w, "文本 → 编码").click();
    await sleep(400);
    eq(await labelArea(w, "编码结果").inputValue(), "U+0058 U+0069 U+0065 U+007A U+0068 U+0069", "Unicode 码点结果");
    return `Xiezhi → "58 69 65 7a 68 69" / "U+0058 U+0069 …"`;
  }, { page });

  await H.run("L-72", "进制转换：Binary 编码与编码 → 文本回转", async () => {
    const w = workbench();
    await selectOn(page, labelSelect(w, "编码方式"), "Binary", { exact: true });
    await labelArea(w, "文本").fill("Hi");
    await button(w, "文本 → 编码").click();
    await sleep(400);
    const bin = await labelArea(w, "编码结果").inputValue();
    eq(bin, "01001000 01101001", "Binary 编码结果");

    await selectOn(page, labelSelect(w, "解码方式"), "Binary", { exact: true });
    await labelArea(w, "文本").fill("");
    await button(w, "编码 → 文本").click();
    await sleep(400);
    eq(await labelArea(w, "文本").inputValue(), "Hi", "Binary 解码结果");
    return `"Hi" → "01001000 01101001" → "Hi"`;
  }, { page });

  await H.shot(page, "L-进制转换");

  /* ---------------- XOR 编解码 ---------------- */

  await H.run("L-73", "XOR 编解码：按密钥循环异或并回转还原", async () => {
    const w = await selectTool(page, "XOR 编解码");
    await labelInput(w, "密钥").fill("key");
    await labelArea(w, "明文 / 输入").fill("password");
    await button(w, "XOR → Hex").click();
    await sleep(400);
    const hex = await labelArea(w, "Hex 输出").inputValue();
    const expected = Buffer.from(
      Array.from(Buffer.from("password", "utf8"), (b, i) => b ^ Buffer.from("key", "utf8")[i % 3]),
    ).toString("hex");
    eq(hex, expected, "XOR Hex 输出");

    await labelArea(w, "待解密 Hex").fill(hex);
    await button(w, "Hex → 文本").click();
    await sleep(400);
    eq(await labelArea(w, "解密结果").inputValue(), "password", "XOR 解密结果");
    return `password ⊕ key = ${hex}，回转还原成功`;
  }, { page });

  await H.shot(page, "L-XOR编解码");

  /* ---------------- 常见端口速查 ---------------- */

  await H.run("L-74", "端口速查：查询 445 命中 SMB", async () => {
    const w = await selectTool(page, "常见端口速查");
    await labelInput(w, "端口").fill("445");
    await button(w, "查询").click();
    await sleep(400);
    const cards = w.locator(".port-hit-list .pentest-hit-card");
    eq(await cards.count(), 1, "命中卡片数量");
    const title = ((await cards.first().locator("header strong").first().textContent()) || "").trim();
    eq(title, "445 / SMB", "端口/服务");
    const note = ((await cards.first().locator("p").first().textContent()) || "").trim();
    contains(note, "永恒之蓝", "风险提示");
    return `445 → ${title}（${note}）`;
  }, { page });

  await H.run("L-75", "端口速查：查询 6379 命中 Redis 未授权风险", async () => {
    const w = workbench();
    await labelInput(w, "端口").fill("6379");
    await button(w, "查询").click();
    await sleep(400);
    const title = ((await w.locator(".port-hit-list .pentest-hit-card header strong").first().textContent()) || "").trim();
    eq(title, "6379 / Redis", "端口/服务");
    contains(((await w.locator(".port-hit-list .pentest-hit-card p").first().textContent()) || ""), "未授权", "风险提示");
    return `6379 → ${title}`;
  }, { page });

  await H.run("L-76", "端口速查：未收录端口标记为未知", async () => {
    const w = workbench();
    await labelInput(w, "端口").fill("12345");
    await button(w, "查询").click();
    await sleep(400);
    const cards = w.locator(".port-hit-list .pentest-hit-card");
    eq(await cards.count(), 1, "命中卡片数量");
    eq(((await cards.first().locator("header strong").first().textContent()) || "").trim(), "12345 / 未知", "未收录端口展示");
    return "12345 → 12345 / 未知";
  }, { page });

  await H.run("L-77", "端口速查：非法端口给出提示并回退到常用列表", async () => {
    const w = workbench();
    await clearMessages(page);
    await labelInput(w, "端口").fill("99999");
    await button(w, "查询").click();
    const msg = await lastMessage(page, { timeout: 8000 });
    must(msg && msg.type === "warning", `非法端口应给出警告，实际 ${msg && msg.type}: ${msg && msg.text}`);
    contains(msg.text, "1-65535", "警告文案");
    await clearMessages(page);
    eq(await w.locator(".port-hit-list .pentest-hit-card").count(), 23, "回退列表条目数");
    return `警告="${msg.text}"，回退展示 23 条常见端口`;
  }, { page });

  await H.run("L-78", "端口速查：显示全部常见端口", async () => {
    const w = workbench();
    await labelInput(w, "端口").fill("445");
    await button(w, "查询").click();
    await sleep(400);
    eq(await w.locator(".port-hit-list .pentest-hit-card").count(), 1, "查询后的条目数");
    await button(w, "显示全部常见端口").click();
    await sleep(400);
    const count = await w.locator(".port-hit-list .pentest-hit-card").count();
    eq(count, 23, "全部常见端口条目数");
    const titles = (await w.locator(".port-hit-list .pentest-hit-card header strong").allTextContents()).map((t) => t.trim());
    eq(titles[0], "21 / FTP", "首条端口");
    eq(titles[titles.length - 1], "27017 / MongoDB", "末条端口");
    return `全部 ${count} 条，从 ${titles[0]} 到 ${titles[titles.length - 1]}`;
  }, { page });

  await H.shot(page, "L-端口速查");

  await settle(page, 300);
  return true;
}

module.exports = { run };
