/*
 * E2E 测试骨架：记录、截图、证据留存与报告生成。
 *
 * 设计原则：所有测试用例必须通过真实浏览器 UI 操作触发，
 * 本模块只负责"记录发生了什么"，不代替用户执行任何业务动作。
 */
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const RUN_DIR = path.join(ROOT, ".run");
const EVIDENCE_DIR = path.join(RUN_DIR, "e2e-evidence");

function timestamp() {
  const d = new Date();
  const p = (n, w = 2) => String(n).padStart(w, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

class Harness {
  constructor(runId) {
    this.runId = runId || timestamp();
    this.dir = path.join(EVIDENCE_DIR, this.runId);
    this.shotDir = path.join(this.dir, "screenshots");
    fs.mkdirSync(this.shotDir, { recursive: true });
    this.cases = [];
    this.apiCalls = [];
    this.consoleErrors = [];
    this.pageErrors = [];
    this.currentPhase = "未分组";
    this.startedAt = new Date();
    this.shotSeq = 0;
  }

  phase(name) {
    this.currentPhase = name;
    console.log(`\n${"=".repeat(70)}\n  ${name}\n${"=".repeat(70)}`);
  }

  /** 记录一条用例结果 */
  record(id, name, status, detail = "", extra = {}) {
    const icon = { PASS: "[PASS]", FAIL: "[FAIL]", SKIP: "[SKIP]", WARN: "[WARN]" }[status] || "[????]";
    const line = `${icon} ${id}  ${name}${detail ? " — " + detail : ""}`;
    console.log(line);
    this.cases.push({
      id,
      phase: this.currentPhase,
      name,
      status,
      detail: String(detail || "").slice(0, 1500),
      at: new Date().toISOString(),
      ...extra,
    });
  }

  /**
   * 执行一个测试用例。fn 抛异常即判定 FAIL。
   * fn 可返回字符串作为通过说明。
   */
  async run(id, name, fn, { page = null, shotOnPass = false } = {}) {
    const started = Date.now();
    try {
      const detail = await fn();
      const ms = Date.now() - started;
      let shot = null;
      if (page && shotOnPass) shot = await this.shot(page, `${id}-pass`);
      this.record(id, name, "PASS", detail || "", { ms, screenshot: shot });
      return { ok: true, value: detail };
    } catch (err) {
      const ms = Date.now() - started;
      let shot = null;
      if (page) {
        try { shot = await this.shot(page, `${id}-FAIL`); } catch { /* 截图失败不掩盖原始错误 */ }
      }
      const msg = (err && err.message) || String(err);
      this.record(id, name, "FAIL", msg.split("\n")[0].slice(0, 500), { ms, screenshot: shot, stack: (err && err.stack || "").slice(0, 2000) });
      return { ok: false, error: err };
    }
  }

  skip(id, name, reason) {
    this.record(id, name, "SKIP", reason);
  }

  warn(id, name, reason) {
    this.record(id, name, "WARN", reason);
  }

  async shot(page, label) {
    this.shotSeq += 1;
    const safe = String(label).replace(/[^\w.-]+/g, "_").slice(0, 80);
    const file = path.join(this.shotDir, `${String(this.shotSeq).padStart(3, "0")}-${safe}.png`);
    try {
      await page.screenshot({ path: file, timeout: 15000 });
      return path.relative(this.dir, file).replace(/\\/g, "/");
    } catch {
      return null;
    }
  }

  /** 挂载页面监听：捕获 UI 触发的 API 调用与控制台错误（作为"由界面驱动"的证据） */
  attach(page) {
    page.on("request", (req) => {
      const url = req.url();
      if (url.includes("/api/")) {
        this.apiCalls.push({
          at: new Date().toISOString(),
          phase: this.currentPhase,
          method: req.method(),
          url: url.replace(/^https?:\/\/[^/]+/, ""),
          initiator: "ui",
        });
      }
    });
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        const t = msg.text();
        // 过滤浏览器扩展/资源加载噪声
        if (/favicon|ERR_CONNECTION_REFUSED.*sockjs|Download the Vue Devtools/i.test(t)) return;
        this.consoleErrors.push({ at: new Date().toISOString(), phase: this.currentPhase, text: t.slice(0, 500) });
      }
    });
    page.on("pageerror", (err) => {
      this.pageErrors.push({ at: new Date().toISOString(), phase: this.currentPhase, text: String(err.message || err).slice(0, 500) });
    });
  }


  get summary() {
    const by = (s) => this.cases.filter((c) => c.status === s).length;
    return {
      total: this.cases.length,
      pass: by("PASS"),
      fail: by("FAIL"),
      skip: by("SKIP"),
      warn: by("WARN"),
    };
  }

  save() {
    const s = this.summary;
    const payload = {
      runId: this.runId,
      startedAt: this.startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      durationSeconds: Math.round((Date.now() - this.startedAt.getTime()) / 1000),
      summary: s,
      cases: this.cases,
      apiCallCount: this.apiCalls.length,
      apiCalls: this.apiCalls,
      consoleErrors: this.consoleErrors,
      pageErrors: this.pageErrors,
    };
    const jsonFile = path.join(this.dir, "result.json");
    fs.writeFileSync(jsonFile, JSON.stringify(payload, null, 2), "utf-8");

    console.log(`\n${"=".repeat(70)}`);
    console.log(`  合计 ${s.total}  通过 ${s.pass}  失败 ${s.fail}  跳过 ${s.skip}  警告 ${s.warn}`);
    console.log(`  证据目录: ${this.dir}`);
    console.log(`${"=".repeat(70)}\n`);
    if (s.fail > 0) {
      console.log("失败用例:");
      for (const c of this.cases.filter((x) => x.status === "FAIL")) {
        console.log(`  - [${c.id}] ${c.name}: ${c.detail}`);
      }
      console.log("");
    }
    return jsonFile;
  }
}

function loadCredentials() {
  const file = path.join(RUN_DIR, "e2e-credentials.json");
  const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
  if (!raw.password) throw new Error("凭据文件缺少 password");
  return raw;
}

module.exports = { Harness, loadCredentials, ROOT, RUN_DIR, EVIDENCE_DIR, timestamp };
