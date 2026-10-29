export type CopilotMode =
  | "ask"
  | "plan"
  | "analyze"
  | "remediate"
  | "troubleshoot"
  | "explain";

export interface CopilotReference {
  type: string;
  id?: string | number;
  title?: string;
  label?: string;
  subtitle?: string;
  summary?: string;
  source?: string;
  targetId?: number;
  data?: Record<string, unknown>;
}

export interface CopilotDraft {
  id: string;
  projectId?: number;
  targetId?: number;
  targetIds?: number[];
  scopeMode?: "SINGLE" | "PROJECT_ALL" | "PROJECT_SUBSET";
  prompt: string;
  mode: CopilotMode;
  refs: CopilotReference[];
  createdAt: number;
  expiresAt: number;
}
