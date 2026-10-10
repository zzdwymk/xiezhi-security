import type { CopilotReference } from "../types/copilot";

interface ScopeTarget { id: number; name: string; enabled: boolean }
interface ScopeApi {
  projects: () => Promise<{ data: { id: number; status: string }[] }>;
  projectTargets: (id: number) => Promise<{ data: { targetId: number }[] }>;
}

function positiveId(value: unknown): number | undefined {
  const id = Number(value);
  return Number.isSafeInteger(id) && id > 0 ? id : undefined;
}

/** Resolve navigation hints against current memberships; the server still validates the audit ID. */
export async function resolveAuditConversationScope<T extends ScopeTarget>(
  refs: CopilotReference[] | undefined,
  targets: T[],
  preferredTargetId: number | undefined,
  preferredProjectId: number | undefined,
  api: ScopeApi,
) {
  if (refs?.length !== 1 || !["audit", "audit-log"].includes(refs[0].type)) return undefined;
  const reference = refs[0];
  const projectId = positiveId(reference.data?.projectId);
  const targetId = positiveId(reference.targetId);
  const availableTargets = targets.filter(target => target.enabled);
  const memberTarget = async (id: number) => {
    const { data } = await api.projectTargets(id);
    const members = new Set(data.map(link => link.targetId));
    const candidates = availableTargets.filter(target => members.has(target.id));
    return targetId
      ? candidates.find(target => target.id === targetId)
      : candidates.find(target => target.id === preferredTargetId) || candidates[0];
  };
  if (projectId) {
    const target = await memberTarget(projectId);
    if (!target) throw new Error("这条审计记录所属项目没有可用的关联目标，请先在项目中核对目标关联与启用状态。");
    return { projectId, target };
  }
  // Target audit entries have no project ID. Include historical projects for read-only review.
  if (!targetId) return undefined;
  if (!availableTargets.some(target => target.id === targetId))
    throw new Error("这条审计记录对应的目标已删除或停用，请先核对目标状态。");
  const { data: projects } = await api.projects();
  const ordered = [...projects].sort((a, b) =>
    Number(b.id === preferredProjectId) - Number(a.id === preferredProjectId)
    || Number(b.status === "ACTIVE") - Number(a.status === "ACTIVE"));
  for (const project of ordered) {
    const target = await memberTarget(project.id);
    if (target) return { projectId: project.id, target };
  }
  throw new Error("这条审计记录对应的目标尚未关联评估项目，请先在项目中关联该目标。");
}
