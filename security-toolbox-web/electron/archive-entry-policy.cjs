"use strict";

// 第394轮：把压缩包条目名的安全校验抽成**纯模块**。
//
// 动机：dependency-worker.cjs 依赖 `original-fs`（Electron 内置模块），在纯 Node 环境下
// require 会失败，导致安全校验无法被单元测试直接覆盖。为了可测试而复制一份实现，
// 是安全测试最常见的形式失效（测试的是副本，生产改坏了测试仍然绿）。
//
// 因此把判定逻辑放在这里：worker 与测试**引用同一份实现**，没有任何副本。

/**
 * 校验并归一化压缩包条目名，防 Zip Slip。
 *
 * @param {unknown} entryName 压缩包内的条目名（可能是任何类型）
 * @returns {{ normalized: string, parts: string[] } | undefined}
 *          合法时返回 POSIX 归一化结果与分段；非法时返回 undefined（调用方应直接拒绝该条目）
 */
function safeArchiveEntryName(entryName) {
  const normalized = String(entryName || "").replace(/\\/g, "/");
  if (!normalized || normalized.includes("\0") || normalized.startsWith("/"))
    return undefined;
  const parts = normalized.split("/");
  if (parts.includes("..") || parts.some((part) => !part)) return undefined;
  return { normalized, parts };
}

module.exports = { safeArchiveEntryName };
