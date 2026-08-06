import { defineStore } from "pinia";
import { endpoints } from "../api";

export type EngineStatus = "checking" | "online" | "offline";

let pollTimer: ReturnType<typeof setInterval> | undefined;
let activeCheck: Promise<void> | undefined;

export const useEngineStore = defineStore("engine", {
  state: () => ({
    status: "checking" as EngineStatus,
    checkedAt: 0,
  }),
  getters: {
    isOnline: (state) => state.status === "online",
    isOffline: (state) => state.status === "offline",
  },
  actions: {
    check() {
      if (activeCheck) return activeCheck;
      activeCheck = (async () => {
        try {
          const { data } = await endpoints.health();
          this.status = data?.status === "UP" ? "online" : "offline";
        } catch {
          this.status = "offline";
        } finally {
          this.checkedAt = Date.now();
          activeCheck = undefined;
        }
      })();
      return activeCheck;
    },
    startPolling() {
      void this.check();
      if (!pollTimer) pollTimer = setInterval(() => void this.check(), 2_500);
    },
    stopPolling() {
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = undefined;
    },
  },
});
