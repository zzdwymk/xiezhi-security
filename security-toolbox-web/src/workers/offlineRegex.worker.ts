import { testRegex } from "../utils/offlinePentest";

self.onmessage = (event: MessageEvent<{ pattern: string; flags: string; input: string }>) => {
  try {
    const { pattern, flags, input } = event.data;
    self.postMessage({ result: testRegex(pattern, flags, input) });
  } catch (error) {
    self.postMessage({ error: error instanceof Error ? error.message : "正则执行失败" });
  }
};
