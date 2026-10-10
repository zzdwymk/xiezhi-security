const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {
  createNotificationCenter, createServiceExitReporter, normalizeNotificationSettings,
  notificationSettingsFromStorage, updateNotificationStorage, safeNotificationRoute, shouldNotify,
} = require("../electron/notification-center.cjs");

const defaults = normalizeNotificationSettings();
assert.equal(defaults.enabled, true);
assert.deepEqual(defaults.severities, ["CRITICAL", "HIGH", "MEDIUM"]);
const saved = updateNotificationStorage({ unrelated: "preserved", taskFailureNotifications: false }, {
  enabled: false, severities: [], approvalNotifications: false,
});
assert.equal(saved.unrelated, "preserved");
assert.equal(saved.notificationEnabled, false);
assert.equal(notificationSettingsFromStorage(saved).taskFailureNotifications, false);
assert.deepEqual(notificationSettingsFromStorage(saved).severities, []);
assert.equal(notificationSettingsFromStorage(saved).approvalNotifications, false);
assert.equal(notificationSettingsFromStorage({ taskCompleteNotifications: false }).taskCompleteNotifications, false);

for (const [category, key] of Object.entries({
  workflow: "workflowCompleteNotifications", workflow_skip: "workflowSkipNotifications",
  approval: "approvalNotifications", schedule: "scheduleNotifications", traffic: "trafficNotifications", service: "serviceNotifications",
})) {
  for (const outcome of ["success", "error", "warning"]) {
    assert.equal(shouldNotify({ category, outcome }, defaults), true);
    assert.equal(shouldNotify({ category, outcome }, { ...defaults, [key]: false }), false);
    assert.equal(shouldNotify({ category, outcome }, { ...defaults, enabled: false }), false);
  }
}
assert.equal(shouldNotify({ category: "unknown" }, defaults), false);
assert.equal(shouldNotify({ category: "task", outcome: "success" }, defaults), true);
const findingsOnly = { ...defaults, taskCompleteNotifications: false };
assert.equal(shouldNotify({ category: "task", outcome: "success", severities: ["HIGH"] }, findingsOnly), true);
assert.equal(shouldNotify({ category: "task", outcome: "success", severities: ["LOW"] }, findingsOnly), false);
assert.equal(shouldNotify({ category: "task", outcome: "success", severities: ["HIGH"] }, { ...findingsOnly, findingNotifications: false }), false);
assert.equal(shouldNotify({ category: "task", outcome: "success", severities: ["HIGH"] }, { ...findingsOnly, severities: [] }), false);
for (const outcome of ["error", "warning"]) {
  assert.equal(shouldNotify({ category: "task", outcome }, findingsOnly), true);
  assert.equal(shouldNotify({ category: "task", outcome }, { ...defaults, taskFailureNotifications: false }), false);
}
for (const route of ["/tasks", "/tasks?taskId=12", "/workflow#run", "/projects/12", "/traffic", "/settings"]) assert.equal(safeNotificationRoute(route), route);
for (const route of ["https://evil.test/tasks", "//evil.test/tasks", "/projects/0", "/tasks/../settings", "/%74asks", "/tasks\\evil", "/tasks\n", "javascript:alert(1)"]) assert.equal(safeNotificationRoute(route), "");

assert.equal(notificationSettingsFromStorage({taskCompleteNotifications:false}).findingNotifications, false);
assert.equal(shouldNotify({category:"task",outcome:"error",severities:["HIGH"]}, {...defaults,taskFailureNotifications:false}), true);
assert.equal(shouldNotify({category:"workflow",outcome:"warning",severities:["HIGH"]}, {...defaults,workflowCompleteNotifications:false}), true);
const instances = [];
let supported = true;
class MockNotification extends EventEmitter {
  static isSupported() { return supported; }
  constructor(options) { super(); this.options = options; instances.push(this); }
  show() { this.shown = true; }
}
const calls = [];
const window = {
  isDestroyed: () => false, isMinimized: () => true,
  restore: () => calls.push("restore"), show: () => calls.push("show"), focus: () => calls.push("focus"),
  webContents: { isDestroyed: () => false, send: (...args) => calls.push(args) },
};
let preferences = defaults;
const center = createNotificationCenter({ Notification: MockNotification, getSettings: () => preferences, getWindow: () => window, maxKeys: 2 });
const notice = { eventKey: "task:1:success", category: "task", outcome: "success", route: "/tasks?taskId=1", title: "任务完成" };
assert.deepEqual(center.show(notice), { delivered: true });
assert.deepEqual(calls, [], "showing a notification must not steal focus");
assert.equal(center.show(notice).reason, "duplicate");
assert.equal(instances.length, 1);
instances[0].emit("click");
assert.deepEqual(calls, ["restore", "show", "focus", ["toolbox:notification-click", "/tasks?taskId=1"]]);
calls.length = 0;
center.show({ ...notice, eventKey: "bad-route", route: "https://evil.test" });
instances.at(-1).emit("click");
assert.deepEqual(calls, ["restore", "show", "focus"], "external routes must never be sent to the renderer");
preferences = { ...defaults, enabled: false };
assert.equal(center.show({ ...notice, eventKey: "disabled" }).reason, "disabled");
preferences = defaults;
supported = false;
assert.equal(center.show({ ...notice, eventKey: "retry" }).reason, "unsupported");
supported = true;
assert.equal(center.show({ ...notice, eventKey: "retry" }).delivered, true);
assert.equal(center.show(notice).delivered, true, "bounded cache evicts the oldest key");
instances.at(-1).emit("failed");
assert.equal(center.show(notice).delivered, true, "native delivery failure must allow a retry");

let quitting = false;
const serviceNotices = [];
const exited = [];
const reporter = createServiceExitReporter({ isQuitting: () => quitting, notify: value => serviceNotices.push(value) });
function child(service, lifecycleId) {
  const process = new EventEmitter();
  reporter.watch(process, { service, lifecycleId, label: service, onUnexpectedExit: code => exited.push(code) });
  return process;
}
const oldAi = child("ai", "old");
reporter.markStopped(oldAi);
const newAi = child("ai", "new");
oldAi.emit("exit", 0);
assert.equal(serviceNotices.length, 0, "late exit of the old process during restart is intentional");
newAi.emit("exit", 1);
assert.equal(serviceNotices.length, 1);
assert.equal(serviceNotices[0].eventKey, "service:ai:new:exit");
assert.equal(serviceNotices[0].category, "service");
assert.equal(serviceNotices[0].route, "/settings");
const java = child("java", "next");
reporter.markStopped(java);
java.emit("exit", 143);
quitting = true;
child("ai", "quit").emit("exit", 0);
assert.equal(serviceNotices.length, 1);
assert.deepEqual(exited, [1], "intentional stop must suppress legacy renderer exit alerts too");

// Execute the real preload bridge and verify listener cleanup and IPC argument isolation.
let bridge;
const ipc = new EventEmitter();
ipc.invoke = (...args) => Promise.resolve(args);
vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../electron/preload.cjs"), "utf8"), {
  require: name => {
    assert.equal(name, "electron");
    return { contextBridge: { exposeInMainWorld: (_name, value) => { bridge = value; } }, ipcRenderer: ipc };
  },
  process: { argv: [], platform: "win32" },
});
const receivedRoutes = [];
const unsubscribe = bridge.onNotificationClick(route => receivedRoutes.push(route));
ipc.emit("toolbox:notification-click", { sender: "private" }, "/tasks");
unsubscribe();
ipc.emit("toolbox:notification-click", {}, "/settings");
assert.deepEqual(receivedRoutes, ["/tasks"]);
let receivedSettings;
const unsubscribeSettings = bridge.onNotificationSettingsChanged(settings => { receivedSettings = settings; });
ipc.emit("toolbox:notification-settings-changed", {}, defaults);
assert.equal(receivedSettings, defaults);
unsubscribeSettings();
assert.equal(ipc.listenerCount("toolbox:notification-settings-changed"), 0);
console.log("Notification center: settings, filters, deduplication, focus, routes, service lifecycle and preload checks passed.");
