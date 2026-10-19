const path = require("node:path");
const { chromium } = require("playwright-core");

const baseUrl = process.env.VISUAL_BASE_URL || "http://localhost:5173";
const browserPath =
  process.env.BROWSER_PATH || "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

(async () => {
  const browser = await chromium.launch({ executablePath: browserPath, headless: true });
  const page = await browser.newPage({ viewport: { width: 1460, height: 900 }, deviceScaleFactor: 1 });
  await page.addInitScript(() => {
    localStorage.setItem("security_toolbox_setup_complete_v2", "true");
    localStorage.setItem("security_toolbox_token", "visual-smoke-token");
  });
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const endpoint = url.pathname.replace(/^\/api/, "");
    const json = (body) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    if (endpoint === "/auth/me")
      return route.fulfill(json({ id: 1, username: "admin", displayName: "admin", role: "ADMIN", permissions: [] }));
    if (endpoint.startsWith("/auth/"))
      return route.fulfill(json({ username: "admin", displayName: "admin", role: "ADMIN" }));
    return route.fulfill(json({}));
  });
  await page.goto(`${baseUrl}/offline-tools`, { waitUntil: "load" }).catch(() => {});
  await page.waitForSelector(".offline-tools-page", { timeout: 20000 }).catch(() => {});
  await page.waitForSelector(".offline-tool-item", { timeout: 20000 }).catch(() => {});
  await page.waitForTimeout(800);

  console.log("pathname:", await page.evaluate(() => location.pathname));
  console.log("offline classes:", await page.evaluate(() => Array.from(document.querySelectorAll("[class*='offline']")).slice(0,30).map(e => e.className).filter((v,i,a)=>a.indexOf(v)===i)));
  console.log("has offline-tools-page:", await page.evaluate(() => !!document.querySelector(".offline-tools-page")));
  console.log("tool items:", await page.evaluate(() => Array.from(document.querySelectorAll(".offline-tool-item")).map((b) => b.textContent.trim())));

  // Click the timestamp tool in the index to reveal it.
  const clicked = await page.evaluate(() => {
    const items = Array.from(document.querySelectorAll(".offline-tool-item"));
    const t = items.find((b) => /时间戳/i.test(b.textContent || ""));
    if (t) { t.click(); return t.textContent.trim(); }
    return null;
  }).catch(() => null);
  console.log("clicked tool:", clicked);
  await page.waitForTimeout(800);
  console.log("has timestamp-tools:", await page.evaluate(() => !!document.querySelector(".timestamp-tools")));

  const info = await page.evaluate(() => {
    const sel = ".timestamp-tools";
    const wrap = document.querySelector(sel);
    if (!wrap) return { found: false };
    const box = (e) => {
      if (!e) return null;
      const r = e.getBoundingClientRect();
      return { top: Math.round(r.top), bottom: Math.round(r.bottom), left: Math.round(r.left), right: Math.round(r.right), h: Math.round(r.height), w: Math.round(r.width) };
    };
    const art = wrap.querySelectorAll("article");
    return {
      found: true,
      articles: Array.from(art).map((a) => {
        const kids = Array.from(a.children).map((k) => {
          const inner = k.shadowRoot ? null : k.querySelector(".el-input, .el-input__wrapper, input.el-input__inner");
          return {
            tag: k.tagName,
            display: getComputedStyle(k).display,
            box: box(k),
            inner: inner
              ? { tag: inner.tagName, cls: inner.className, display: getComputedStyle(inner).display, box: box(inner) }
              : null,
          };
        });
        return { kids };
      }),
    };
  });
  console.log(JSON.stringify(info, null, 2));

  await page.screenshot({ path: path.join(__dirname, "offline-timestamp.png"), fullPage: false });
  console.log("saved offline-timestamp.png");
  await browser.close();
})();
