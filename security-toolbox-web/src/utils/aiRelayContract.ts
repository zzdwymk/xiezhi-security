// AI 中转超时与上限的单一契约（第402轮）。
// 这里的数值必须与 electron/ai-relay.cjs 的 AI_RELAY_DEFAULTS 保持一致；
// scripts/test-ai-relay-contract.cjs 会在测试中比对两处，防止界面文案与实现再次漂移。
export const AI_RELAY_ATTEMPT_TIMEOUT_SECONDS = 120;
export const AI_RELAY_TOTAL_TIMEOUT_SECONDS = 150;
export const AI_RELAY_COOLDOWN_SECONDS = 5;
export const AI_RELAY_MAX_PROMPT_CHARS = 4000;
export const AI_RELAY_MAX_PROVIDERS = 16;

export function relayDeadlineHelp(): string {
  return [
    "每次请求每条线路最多尝试一次；",
    `单线路最多 ${AI_RELAY_ATTEMPT_TIMEOUT_SECONDS} 秒，总计最多 ${AI_RELAY_TOTAL_TIMEOUT_SECONDS} 秒，失败冷却 ${AI_RELAY_COOLDOWN_SECONDS} 秒。`,
    "收到模型回答后展示；被上游截断或仅有推理内容时，回答会带救援标记。",
    "启停会短暂重启服务，线路修改保存后对新请求生效。",
    `最多 ${AI_RELAY_MAX_PROVIDERS} 条线路。`,
  ].join("");
}