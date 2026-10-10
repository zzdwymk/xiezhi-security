// Exercise the real Settings view with browser notification and HTTP fixtures.
const assert = require("node:assert/strict");
const path = require("node:path");
const { chromium } = require("playwright-core");
const root = path.resolve(__dirname, "..");
let browser, server;
const errors = [];
const html = `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';
import {createPinia} from 'pinia';
import {createRouter, createMemoryHistory, RouterView} from 'vue-router';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import '/src/unified-theme.css';
import Settings from '/src/views/Settings.vue';
import {loadNotificationPreferences} from '/src/utils/notifications.ts';
const router = createRouter({history:createMemoryHistory(),routes:[{path:'/settings',component:Settings}]});
await router.push('/settings');
await router.isReady();
window.fixture.readPreferences = loadNotificationPreferences;
createApp(RouterView).use(createPinia()).use(router).use(ElementPlus).mount('#app');
</script></body></html>`;

(async () => {
  const { createServer } = await import("vite");
  const vue = (await import("@vitejs/plugin-vue")).default;
  server = await createServer({
    configFile: false, root, cacheDir: path.resolve(root, "../.run/notification-settings-cache"),
    optimizeDeps: { entries: ["src/views/Settings.vue"], include: ["vue", "pinia", "vue-router", "element-plus"] },
    plugins: [vue(), {
      name: "notification-settings-fixture",
      configureServer(s) {
        s.middlewares.use(async (req, res, next) => {
          if (req.url !== "/__notifications") return next();
          res.setHeader("Content-Type", "text/html");
          res.end(await s.transformIndexHtml(req.url, html));
        });
      },
    }],
    server: { host: "127.0.0.1", port: 0, hmr: false, watch: { ignored: ["**/dist/**", "**/desktop-release/**", "**/tools/**"] } }, logLevel: "error",
  });
  await server.listen();
  browser = await chromium.launch({
    executablePath: process.env.NOTIFICATION_TEST_BROWSER || "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(12000);
  page.on("pageerror", error => errors.push(error.message));
  await page.addInitScript(() => {
    window.fixture = { permissionRequests: 0 };
    window.Notification = class {
      static permission = "default";
      static async requestPermission() {
        window.fixture.permissionRequests++;
        this.permission = "granted";
        return "granted";
      }
    };
  });
  await page.route("**/api/**", route => route.fulfill({ status: 200, json: { maxConcurrentTasks: 3, runningTasks: 0, dependencies: [] } }));
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__notifications`, { timeout: 90000, waitUntil: "domcontentloaded" });
  const open = () => page.getByRole("button", { name: /通知偏好/ }).click();
  await open();
  const dialog = page.getByRole("dialog", { name: "系统通知", exact: true });
  await dialog.waitFor();
  assert.equal(await page.evaluate(() => window.fixture.permissionRequests), 0, "mount and opening preferences must not request permission");
  await dialog.getByRole("button", { name: "允许浏览器通知", exact: true }).click();
  assert.equal(await page.evaluate(() => window.fixture.permissionRequests), 1);
  await dialog.getByText("已允许。应用在后台时可发送系统通知。", { exact: true }).waitFor();
  const master = dialog.getByRole("switch", { name: "允许系统通知", exact: true });
  const completed = dialog.getByRole("switch", { name: "任务完成", exact: true });
  await master.locator("..").click();
  assert.equal(await completed.isDisabled(), true, "master toggle disables the category controls");
  await master.locator("..").click();
  await completed.locator("..").click();
  await dialog.getByRole("switch", { name: "任务异常", exact: true }).locator("..").click();
  await dialog.getByRole("switch", { name: "执行确认", exact: true }).locator("..").click();
  for (const name of ["严重（Critical）", "高危（High）", "中危（Medium）"]) {
    await dialog.getByText(name, { exact: true }).click();
    assert.equal(await dialog.getByRole("checkbox", { name, exact: true }).isChecked(), false);
  }
  await dialog.getByRole("button", { name: "保存", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  const settings = await page.evaluate(() => window.fixture.readPreferences());
  assert.equal(settings.enabled, true);
  assert.equal(settings.taskCompleteNotifications, false);
  assert.equal(settings.taskFailureNotifications, false);
  assert.equal(settings.approvalNotifications, false);
  assert.equal(settings.findingNotifications, true);
  assert.deepEqual(settings.severities, []);
  await open();
  await dialog.waitFor();
  assert.equal(await completed.isChecked(), false);
  assert.equal(await dialog.getByRole("switch", { name: "执行确认", exact: true }).isChecked(), false);
  assert.equal(await dialog.getByRole("checkbox", { name: "高危（High）", exact: true }).isChecked(), false);
  assert.equal(await page.evaluate(() => window.fixture.permissionRequests), 1, "reopening settings must not prompt again");
  assert.deepEqual(errors, []);
  console.log("Notification settings browser: explicit permission, all categories, master toggle and empty severity persistence passed.");
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await browser?.close();
  await server?.close();
});
