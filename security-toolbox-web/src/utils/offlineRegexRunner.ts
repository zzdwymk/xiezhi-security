import type { testRegex } from "./offlinePentest";

type RegexResult = ReturnType<typeof testRegex>;
type RegexReply = { result: RegexResult } | { error: string };

// The factory keeps the lifecycle independently testable with a real worker.
export interface RegexWorker {
  onmessage: ((event: MessageEvent<RegexReply>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  postMessage(request: { pattern: string; flags: string; input: string }): void;
  terminate(): void;
}

export function createRegexRunner(createWorker: () => RegexWorker, timeoutMs = 1500) {
  let cancelCurrent: (() => void) | undefined;
  return {
    cancel() { cancelCurrent?.(); },
    run(pattern: string, flags: string, input: string): Promise<RegexResult> {
      cancelCurrent?.();
      return new Promise((resolve, reject) => {
        let worker: RegexWorker;
        try { worker = createWorker(); }
        catch { reject(new Error("无法启动正则处理，请重试")); return; }
        let settled = false;
        const finish = (result?: RegexResult, error?: Error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          worker.onmessage = null;
          worker.onerror = null;
          worker.terminate();
          if (cancelCurrent === cancel) cancelCurrent = undefined;
          if (error) reject(error); else resolve(result!);
        };
        const cancel = () => finish(undefined, new Error("正则执行已取消"));
        cancelCurrent = cancel;
        const timer = setTimeout(() => finish(undefined, new Error("正则执行超时，请简化表达式或减少输入后重试")), timeoutMs);
        worker.onmessage = ({ data }) => {
          if ("error" in data) finish(undefined, new Error(data.error));
          else finish(data.result);
        };
        worker.onerror = () => finish(undefined, new Error("正则执行失败，请检查表达式后重试"));
        try { worker.postMessage({ pattern, flags, input }); }
        catch { finish(undefined, new Error("无法提交正则输入，请重试")); }
      });
    },
  };
}
