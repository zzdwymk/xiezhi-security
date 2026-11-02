/*
 * 纯逻辑仿真：验证“聊天框待发队列”状态机不丢消息、不卡队列、顺序正确。
 *
 * 这里不加载 Vue，而是把 Dashboard.vue 里 pendingPrompts / maybeDrainThread / isThreadBusy
 * 的核心规则抽成等价模型，覆盖关键场景：
 *   1) 连发 N 条（当前对话忙）→ 依次串行发出，顺序不变，全部发出。
 *   2) 出队某条 launch 提前 return（模拟归属对话被删除）→ 剩余队列继续排空，不卡死。
 *   3) 取消中间一条 → 其余按序发送。
 *   4) 不同对话键互不影响。
 *
 * 用法：node scripts/test-prompt-queue-logic.cjs
 */
const assert = require("node:assert");

function createHarness({ launchDelayMs = 5, failToTakeLockFor = new Set() } = {}) {
  // 等价状态
  const pendingPrompts = new Map(); // key -> array of {id}
  const busy = new Set(); // 等价 activeSendingThreadIds
  const draining = new Set();
  const sent = []; // 发送顺序记录
  const log = [];

  const isThreadBusy = (key) => busy.has(key);

  function enqueue(key, item) {
    const list = pendingPrompts.get(key) ?? [];
    list.push(item);
    pendingPrompts.set(key, list);
  }

  async function launch(item, key) {
    // 模拟“归属对话已被删除 → 未真正占锁就 return”
    if (failToTakeLockFor.has(key) && item.forFail) {
      log.push(`drop:${item.id}`);
      return;
    }
    busy.add(key);
    try {
      await new Promise((r) => setTimeout(r, launchDelayMs));
      sent.push(item.id);
      log.push(`sent:${item.id}`);
    } finally {
      busy.delete(key);
      // 关键：真实实现里 launchPrompt 的 finally 会再次尝试出队
      maybeDrain(key);
    }
  }

  function maybeDrain(key) {
    if (draining.has(key)) return;
    const list = pendingPrompts.get(key);
    if (!list || !list.length) return;
    if (isThreadBusy(key)) return;
    draining.add(key);
    const next = list[0];
    const rest = list.slice(1);
    if (rest.length) pendingPrompts.set(key, rest);
    else pendingPrompts.delete(key);
    try {
      Promise.resolve(launch(next, key)).then(() => {
        if (!isThreadBusy(key) && (pendingPrompts.get(key)?.length ?? 0) > 0) maybeDrain(key);
      });
    } finally {
      draining.delete(key);
    }
  }

  return { pendingPrompts, busy, sent, log, enqueue, maybeDrain, isThreadBusy };
}

function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

(async () => {
  // 场景 1：连发 3 条，全部串行发出，顺序正确
  {
    const h = createHarness();
    const key = "t1";
    h.enqueue(key, { id: 1 });
    h.enqueue(key, { id: 2 });
    h.enqueue(key, { id: 3 });
    // 模拟第一条已在处理中：先占锁再出队
    h.busy.add(key);
    // 直接调用 drain 会被 busy 挡住
    h.maybeDrain(key);
    await wait(2);
    assert.deepStrictEqual(h.sent, [], "忙时不应发送");
    h.busy.delete(key); // 第一轮结束
    h.maybeDrain(key);
    await wait(100);
    assert.deepStrictEqual(h.sent, [1, 2, 3], "应全部按序发出");
    assert.strictEqual(h.pendingPrompts.get(key), undefined, "队列应排空");
    console.log("[PASS] 场景1 连发3条按序串行发出，无丢失无卡死");
  }

  // 场景 2：出队某条 launch 提前 return，剩余继续排空
  {
    const h = createHarness({ failToTakeLockFor: new Set(["t2"]) });
    const key = "t2";
    h.enqueue(key, { id: 10, forFail: true }); // 第一条被“删除对话”丢弃
    h.enqueue(key, { id: 11 });
    h.enqueue(key, { id: 12 });
    h.maybeDrain(key);
    await wait(100);
    // 第一条被丢弃，11、12 仍应发出
    assert.deepStrictEqual(h.sent, [11, 12], "被丢弃项之后的队列应继续排空");
    assert.strictEqual(h.pendingPrompts.get(key), undefined, "队列应最终排空");
    console.log("[PASS] 场景2 首条提前return不阻塞后续，剩余正常发出");
  }

  // 场景 3：取消中间一条
  {
    const h = createHarness();
    const key = "t3";
    h.enqueue(key, { id: 21 });
    h.enqueue(key, { id: 22 });
    h.enqueue(key, { id: 23 });
    // 取消 22
    const list = h.pendingPrompts.get(key).filter((x) => x.id !== 22);
    h.pendingPrompts.set(key, list);
    h.maybeDrain(key);
    await wait(100);
    assert.deepStrictEqual(h.sent, [21, 23], "取消中间项后其余按序发出");
    console.log("[PASS] 场景3 取消中间项，剩余按序发出");
  }

  // 场景 4：两个对话键互不影响
  {
    const h = createHarness();
    h.enqueue("a", { id: 31 });
    h.enqueue("a", { id: 32 });
    h.enqueue("b", { id: 41 });
    h.busy.add("a"); // a 忙，b 空闲
    h.maybeDrain("a");
    h.maybeDrain("b");
    await wait(50);
    // b 应先发出，a 仍等待
    assert.deepStrictEqual(h.sent, [41], "空闲对话b先发，忙的a等待");
    h.busy.delete("a");
    h.maybeDrain("a");
    await wait(100);
    assert.deepStrictEqual(h.sent.sort(), [31, 32, 41], "两对话都最终排空");
    console.log("[PASS] 场景4 不同对话键互不影响");
  }

  console.log("\nALL QUEUE LOGIC TESTS PASSED");
})().catch((e) => {
  console.error("TEST FAILED:", e.message);
  process.exit(1);
});
