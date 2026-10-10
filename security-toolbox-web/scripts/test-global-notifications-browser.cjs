// Real App.vue, global feed/delivery, Vue Router and Pinia; every backend request is mocked.
const assert = require("node:assert/strict");
const path = require("node:path");
const { chromium } = require("playwright-core");
const root = path.resolve(__dirname, "..");
let browser, server;
const errors = [];
const requests = [];
let items = [], cursor = 0;
const html = `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp, h, nextTick} from 'vue';
import {createPinia} from 'pinia';
import {createRouter, createMemoryHistory} from 'vue-router';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import '/src/unified-theme.css';
import App from '/src/App.vue';
import {useAuthStore} from '/src/stores/auth.ts';
import {storeAuthToken} from '/src/authToken.ts';
import {saveNotificationPreferences} from '/src/utils/notifications.ts';
const page = {render:()=>h('div',{'data-testid':'current-view'},router.currentRoute.value.fullPath)};
const router = createRouter({history:createMemoryHistory(),routes:[
  ...['/tasks','/settings','/workflow','/traffic','/projects/:id','/'].map(path=>({path,component:page})),
  {path:'/login',component:page,meta:{public:true}}
]});
const pinia = createPinia();
storeAuthToken('notification-fixture-token',false);
const auth = useAuthStore(pinia);
auth.token = 'notification-fixture-token'; auth.user = {username:'notification-tester',role:'ADMIN'}; auth.checked = true;
await router.push('/tasks'); await router.isReady();
Object.assign(window.fixture,{router,auth,save:saveNotificationPreferences,flush:nextTick});
createApp(App).use(pinia).use(router).use(ElementPlus).mount('#app');
</script></body></html>`;

function taskNotice(id) {
  return { id, eventKey: `task:${id}:success`, category: "task", outcome: "success",
    title: `全局任务完成 ${id}`, body: "模拟任务已经完成，可点击查看结果。", route: `/tasks?taskId=${id}`, severities: [] };
}

(async () => {
  const { createServer } = await import("vite");
  const vue = (await import("@vitejs/plugin-vue")).default;
  server = await createServer({
    configFile: false, root, cacheDir: path.resolve(root, "../.run/global-notifications-cache"),
    optimizeDeps: { entries: ["src/App.vue"], include: ["vue", "pinia", "vue-router", "element-plus"] },
    plugins: [vue(), {
      name: "global-notifications-fixture",
      configureServer(s) {
        s.middlewares.use(async (req, res, next) => {
          if (req.url !== "/__notifications") return next();
          res.setHeader("Content-Type", "text/html");
          res.end(await s.transformIndexHtml(req.url, html));
        });
      },
    }],
    server: { host: "127.0.0.1", port: 0, hmr: false, watch: { ignored: ["**/dist/**", "**/desktop-release/**", "**/tools/**"] } },
    logLevel: "error",
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
    localStorage.clear(); sessionStorage.clear();
    window.fixture = { permissionRequests: 0, browserNotices: 0, presented: [] };
    Object.defineProperty(document, "hidden", { get: () => false });
    document.hasFocus = () => true;
    window.Notification = class {
      static permission = "default";
      static async requestPermission() { window.fixture.permissionRequests++; return "default"; }
      constructor() { window.fixture.browserNotices++; }
    };
    const observer = new MutationObserver(records => {
      for (const record of records) for (const node of record.addedNodes) {
        if (node instanceof HTMLElement && node.matches(".el-notification")) window.fixture.presented.push(node.textContent);
      }
    });
    observer.observe(document, { childList: true, subtree: true });
  });
  await page.route("**/api/**", async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/notifications") {
      requests.push({ after: url.searchParams.get("after"), authorization: request.headers().authorization });
      // Intentionally include already delivered items to exercise client-side deduplication.
      await route.fulfill({ status: 200, json: { items, cursor } });
    } else if (url.pathname === "/api/system/health") {
      await route.fulfill({ status: 200, json: { status: "UP" } });
    } else {
      errors.push(`Unexpected API request: ${url.pathname}`);
      await route.fulfill({ status: 500, json: { message: "Unexpected fixture request" } });
    }
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__notifications`, { timeout: 90000, waitUntil: "domcontentloaded" });
  await page.getByTestId("current-view").waitFor();
  await page.waitForFunction(() => Object.keys(localStorage).some(key => key.startsWith("security_toolbox_notification_cursor_v1:") && localStorage.getItem(key) === "0"));
  assert.equal(requests[0].after, null);
  assert.equal(requests[0].authorization, "Bearer notification-fixture-token");
  assert.equal(await page.evaluate(() => window.fixture.permissionRequests), 0);

  await page.evaluate(() => window.fixture.router.push("/settings"));
  const beforeRoutePoll = requests.length;
  // Let the actual 2.5 second timer run: switching workspace views must keep polling alive.
  await page.waitForResponse(response => new URL(response.url()).pathname === "/api/notifications");
  assert.ok(requests.length > beforeRoutePoll);
  assert.equal(requests.at(-1).after, "0", "workspace navigation retains the global cursor");
  assert.equal(await page.getByTestId("current-view").textContent(), "/settings");

  async function pollAndWaitForCursor(value) {
    await page.evaluate(() => window.dispatchEvent(new Event("focus")));
    await page.waitForFunction(value => Object.keys(localStorage).some(key => key.startsWith("security_toolbox_notification_cursor_v1:") && localStorage.getItem(key) === String(value)), value);
  }
  items = [taskNotice(17)]; cursor = 17;
  await pollAndWaitForCursor(17);
  const first = page.locator(".el-notification").filter({ hasText: "全局任务完成 17" });
  await first.waitFor();
  assert.equal(await first.count(), 1);
  assert.equal(await page.evaluate(() => window.fixture.presented.length), 1);
  const repeated = page.waitForResponse(response => new URL(response.url()).pathname === "/api/notifications");
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await (await repeated).finished();
  await page.evaluate(() => window.fixture.flush());
  assert.equal(await page.evaluate(() => window.fixture.presented.length), 1, "duplicate backend delivery creates only one foreground notification");
  await first.click();
  await page.waitForFunction(() => window.fixture.router.currentRoute.value.fullPath === "/tasks?taskId=17");

  await page.evaluate(() => window.fixture.save({ enabled: false }));
  items = [taskNotice(18)]; cursor = 18;
  await pollAndWaitForCursor(18);
  assert.equal(await page.evaluate(() => window.fixture.presented.length), 1, "disabled preferences filter new items without stalling the feed");
  assert.equal(await page.locator(".el-notification").filter({ hasText: "全局任务完成 18" }).count(), 0);
  await page.evaluate(() => window.fixture.save({ enabled: true }));
  const afterEnable = page.waitForResponse(response => new URL(response.url()).pathname === "/api/notifications");
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await (await afterEnable).finished();
  await page.evaluate(() => window.fixture.flush());
  assert.equal(await page.evaluate(() => window.fixture.presented.length), 1, "reenabling does not replay muted history");

  // The App must preserve the record selectors consumed by the workspace pages.
  for (const notice of [
    { id: 19, eventKey: "workflow:19:failed", category: "workflow", outcome: "error", title: "工作流记录可查看", body: "模拟工作流异常结束。", route: "/workflow?runId=19" },
    { id: 20, eventKey: "approval:20:pending", category: "approval", outcome: "warning", title: "项目方案等待确认", body: "模拟 AI 方案需要管理员确认。", route: "/projects/3?approvalId=20" },
  ]) {
    items = [notice]; cursor = notice.id;
    await pollAndWaitForCursor(notice.id);
    const notification = page.locator(".el-notification").filter({ hasText: notice.title });
    await notification.waitFor();
    await notification.click();
    await page.waitForFunction(route => window.fixture.router.currentRoute.value.fullPath === route, notice.route);
  }
  assert.equal(await page.evaluate(() => window.fixture.permissionRequests), 0, "the global subscription never prompts for notification permission");
  assert.equal(await page.evaluate(() => window.fixture.browserNotices), 0, "foreground notices stay in the app");
  assert.deepEqual(errors, []);
  console.log("Global notifications browser: App polling survives route changes, authenticated cursor persists, foreground delivery deduplicates, task/workflow/approval clicks preserve record queries, preferences mute, no automatic permission prompt.");
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await browser?.close();
  await server?.close();
});
