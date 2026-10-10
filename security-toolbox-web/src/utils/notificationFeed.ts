import type { SystemNotice } from "./notifications";

export interface NotificationPage { items: SystemNotice[]; cursor: number }
export interface NotificationFeedOptions {
  fetchPage: (after: number | undefined, signal: AbortSignal) => Promise<NotificationPage>;
  deliver: (items: SystemNotice[]) => Promise<void>;
  readCursor: () => number | undefined;
  saveCursor: (cursor: number) => void;
  intervalMs?: number;
}

/** One feed per signed-in user. The cursor advances only after delivery finishes. */
export function startNotificationFeed(options: NotificationFeedOptions) {
  let cursor = options.readCursor();
  let stopped = false;
  let pending: Promise<void> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let controller: AbortController | undefined;
  let failures = 0;
  let requestTimeout: ReturnType<typeof setTimeout> | undefined;
  const interval = options.intervalMs ?? 2500;
  const poll = (): Promise<void> => {
    if (stopped) return Promise.resolve();
    if (pending) return pending;
    clearTimeout(timer);
    controller = new AbortController();
    const requestController = controller;
    requestTimeout = setTimeout(() => requestController.abort(), 15_000);
    pending = (async () => {
      try {
        const page = await options.fetchPage(cursor, controller!.signal);
        if (stopped) return;
        if (!Array.isArray(page.items) || !Number.isSafeInteger(page.cursor) || page.cursor < 0)
          throw new Error("通知数据格式无效");
        await options.deliver(page.items);
        if (stopped) return;
        cursor = page.cursor;
        options.saveCursor(cursor);
        failures = 0;
      } catch {
        failures = Math.min(4, failures + 1);
      } finally {
        clearTimeout(requestTimeout);
        pending = undefined;
        if (!stopped) timer = setTimeout(() => void poll(), Math.min(30_000, interval * 2 ** failures));
      }
    })();
    return pending;
  };
  void poll();
  return {
    poll,
    stop() { stopped = true; clearTimeout(timer); clearTimeout(requestTimeout); controller?.abort(); },
  };
}
