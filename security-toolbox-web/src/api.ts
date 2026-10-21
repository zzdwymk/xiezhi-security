import { readAuthToken } from "./authToken";
import { api, apiFetch, apiUrl } from "./apiClient";
import { taskbarProgress } from "./utils/taskbarProgress";
import { publicProgressProvenance } from "./utils/aiPresentation";
import { assertAiLegacyFallbackAllowed, normalizeAiExecutionDecision, type AiExecutionIntent } from "./utils/aiIntent";
import type { CopilotMode, CopilotReference } from "./types/copilot";
import type {
  ConversationAgentEvent,
  ConversationAgentEventType,
  ConversationCitation,
  ConversationStep,
  PublicAgentNodeStatus,
} from "./stores/conversations";

export { api } from "./apiClient";

export interface Target {
  id: number;
  name: string;
  targetValue: string;
  targetType: string;
  authorizationNote: string;
  allowedPorts: string;
  enabled: boolean;
  authorizationValidFrom?: string;
  authorizationExpiresAt?: string;
  projectId?: number;
}

export interface PlanStep {
  risk?: string;
  requiresApproval?: boolean;
  workflowNodeId?: string;
  nodeRunId?: string;
  group?: number;
  dependsOnNodeIds?: string[];
  toolCode: string;
  title: string;
  reason: string;
  parameters: Record<string, unknown>;
}

export interface AiPlan {
  provider: string;
  model: string;
  summary: string;
  requiresConfirmation: boolean;
  targetId: number;
  objective: string;
  steps: PlanStep[];
}

export interface AiDispatch {
  approvalId?: number | string;
  approvalStatus?: string;
  targetId: number;
  plan: Omit<AiPlan, "targetId" | "objective">;
  taskCount: number;
  taskIds: number[];
  /** Agent runs may finish with an answer without creating a task. */
  answer?: string;
  citations?: ConversationCitation[];
  runId?: string;
  workflowId?: string;
  workflowRevision?: number;
  workflowDigest?: string;
  outerNodeId?: string;
  nodeRunId?: string;
  ledgerDigest?: string;
  terminationReason?: string;
}

export interface AiAgentRequestPayload {
  projectId?: number;
  targetId: number;
  sessionId?: string;
  turnId?: string;
  workflowId?: string;
  workflowRevision?: number;
  workflowDigest?: string;
  outerNodeId?: string;
  nodeRunId?: string;
  prompt: string;
  execute?: boolean;
  executionIntent?: AiExecutionIntent;
  userPrompt?: string;
  mode?: CopilotMode;
  contextRefs?: Record<string, unknown>;
  refs?: CopilotReference[];
}

interface AiAgentResponsePayload {
  approvalId?: number | string;
  approvalStatus?: string;
  sessionId?: string;
  projectId?: number;
  targetId: number;
  message?: string;
  plan?: AiDispatch["plan"];
  taskIds?: number[];
  workflowId?: string;
  workflowRevision?: number;
  workflowDigest?: string;
  outerNodeId?: string;
  nodeRunId?: string;
  ledgerDigest?: string;
  terminationReason?: string;
}

export interface AiDispatchProgress {
  type: "progress";
  stage?: string;
  summary?: string;
  message?: string;
  data?: unknown;
  dispatch?: AiDispatch;
}

export interface AgentStreamEvent extends ConversationAgentEvent {
  type: ConversationAgentEventType;
  dispatch?: AiDispatch;
  plan?: Partial<AiPlan> & {
    steps?: Array<Partial<PlanStep> & Record<string, unknown>>;
  };
  steps?: Array<Partial<PlanStep> & Record<string, unknown>>;
  taskCount?: number;
  taskIds?: number[];
  targetId?: number;
  answer?: string;
  citations?: ConversationCitation[];
  [key: string]: unknown;
}

export type AiDispatchStreamEvent =
  | AiDispatchProgress
  | AgentStreamEvent
  | {
      type: "tasks" | "done" | "error" | string;
      stage?: string;
      summary?: string;
      message?: string;
      targetId?: number;
      plan?: AiDispatch["plan"];
      taskCount?: number;
      taskIds?: number[];
      data?: unknown;
      dispatch?: AiDispatch;
      answer?: string;
      citations?: ConversationCitation[];
      [key: string]: unknown;
    };

export interface AiAnswer {
  answer: string;
  provider: string;
  taskIds: number[];
  summary?: string;
  citations?: ConversationCitation[];
}

export interface VulnerabilityDefinition {
  id: number;
  vulnerabilityCode: string;
  name: string;
  severity: string;
  category: string;
  description: string;
  detectionGuidance: string;
  remediation: string;
  referenceUrls?: string;
  sourceType?: string;
  sourceName?: string;
  sourceExternalId?: string;
  sourceVersion?: string;
  sourceUrl?: string;
  templateRelativePath?: string;
  templateSha256?: string;
  templateSigned?: boolean;
  protocols?: string;
  authors?: string;
  tags?: string;
  cveIds?: string;
  cweIds?: string;
  cvssScore?: number;
  epssScore?: number;
  knownExploited?: boolean;
  verificationStatus?: string;
  scanSafety?: string;
  requiresInteractsh?: boolean;
  sourceActive?: boolean;
  sourceUpdatedAt?: string;
}

export interface DependencyStatus {
  name: string;
  status?: string;
  installed?: boolean;
  version?: string;
  path?: string;
  required?: boolean;
  category?: string;
  message?: string;
  hash?: string;
  dirHash?: string;
  output?: string;
}

export interface SystemDependenciesResponse {
  os?: string;
  arch?: string;
  database?: string;
  dependencies?: DependencyStatus[];
  items?: DependencyStatus[];
  developmentMode?: boolean;
}

export interface PageResponse<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  number: number;
  size: number;
}

export interface ScanDiff {
  baselineTaskId: number;
  currentTaskId: number;
  targetId: number;
  generatedAt: string;
  summary: {
    baselineCount: number;
    currentCount: number;
    added: number;
    persistent: number;
    resolved: number;
    severityChanged: number;
  };
  items: Array<{
    changeType: string;
    fingerprint: string;
    baselineFindingId?: number;
    currentFindingId?: number;
    title: string;
    previousSeverity?: string;
    currentSeverity?: string;
    ruleCode?: string;
    vulnerabilityCode?: string;
  }>;
}
export interface ScanSchedule {
  id: number;
  projectId: number;
  targetId: number;
  toolCode: string;
  parametersJson?: string;
  cronExpression?: string;
  intervalSeconds?: number;
  enabled: boolean;
  nextRunAt?: string;
  lastRunAt?: string;
  lastTaskId?: number;
  lastError?: string;
}
export interface TaskControlStatus {
  maxConcurrentTasks: number;
  availableConcurrentSlots: number;
  maxConcurrentTasksPerTarget: number;
  queueCapacity: number;
  pendingTasks: number;
  runningTasks: number;
}
export interface TaskExecutionLimitView {
  maxConcurrentTasks: number;
}
export interface AssessmentProject {
  id: number;
  name: string;
  description?: string;
  authorizationStatement: string;
  authorizationValidFrom: string;
  authorizationExpiresAt: string;
  status: string;
  owner: string;
  createdAt: string;
  updatedAt?: string;
}
export interface ProjectTarget {
  id: number;
  projectId: number;
  targetId: number;
}
export interface ProjectSummary {
  project: AssessmentProject;
  targetCount: number;
  taskCount: number;
  vulnerabilityCount: number;
  informationalCount: number;
  retestCount: number;
  auditCount: number;
}
export interface WorkflowNode {
  id: string;
  label: string;
  kind: string;
  desc: string;
  removable?: boolean;
}
export interface WorkflowEdge {
  source: string;
  target: string;
  conditional?: boolean;
}
export interface WorkflowGraph {
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  compiled?: { nodes: string[]; edges: WorkflowEdge[] } | null;
  source: "langgraph" | "static";
}
export interface WorkflowStepSpec {
  nodeId?: string;
  tool: string;
  label?: string;
  parameters?: Record<string, unknown>;
  risk?: string;
  requiresApproval?: boolean;
  group?: number;
  dependsOnNodeIds?: string[];
}
export interface WorkflowGraphNodeSpec {
  id: string;
  type: string;
  label: string;
  phase: string;
  tool?: string;
  position: { x: number; y: number };
}
export interface WorkflowGraphEdgeSpec {
  id: string;
  source: string;
  target: string;
}
export interface WorkflowSpecV2 {
  workflowId?: string;
  scopeId?: number;
  revision?: number;
  specDigest?: string;
  updatedBy?: string;
  updatedAt?: string;
  version?: number;
  preset?: string;
  steps?: WorkflowStepSpec[];
  graph?: { nodes: WorkflowGraphNodeSpec[]; edges: WorkflowGraphEdgeSpec[] };
}

export interface WorkflowRunNodeIssue {
  nodeId: string;
  toolCode: string;
  label: string;
  reason: string;
}

export interface WorkflowRunPreflight {
  workflowId: string;
  workflowRevision: number;
  workflowDigest: string;
  issues: WorkflowRunNodeIssue[];
  resolvedTargets?: Record<string, string[]>;
}

export interface WorkflowRunSummary {
  id: number;
  projectId: number;
  targetId: number;
  workflowId: string;
  workflowRevision: number;
  workflowDigest: string;
  status: string;
  progress: number;
  message?: string;
  taskCount: number;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
}

export interface WorkflowRunDetail {
  run: WorkflowRunSummary;
  spec: WorkflowSpecV2;
  tasks: ProjectTaskRecord[];
}

export interface WorkflowSuggestionAction {
  type: "add_tool" | "focus_node" | string;
  tool?: string;
  phase?: string;
  nodeId?: string;
}
export interface WorkflowSuggestion {
  id: string;
  kind: string;
  severity: "info" | "warning" | string;
  title: string;
  detail: string;
  action?: WorkflowSuggestionAction;
}
export interface WorkflowSuggestResponse {
  source: string;
  model?: string;
  note?: string;
  suggestions: WorkflowSuggestion[];
  generatedAt?: string;
}

export interface MemoryDoc {
  id: string;
  title: string;
  source: string;
  chars: number;
  conversationId?: string;
  createdAt?: string;
}
export interface DiscoveryEvidence {
  type?: string;
  name?: string;
  value?: string;
  source?: string;
  detail?: string;
  [key: string]: unknown;
}
export interface DiscoveryResult {
  id?: number;
  projectId: number;
  targetId: number;
  targetValue?: string;
  url?: string;
  server?: string;
  framework?: string;
  fingerprint?: string | Record<string, unknown>;
  technologies?: string | Array<Record<string, unknown>>;
  waf?: string | Record<string, unknown>;
  wafName?: string;
  confidence?: number;
  evidence?: DiscoveryEvidence[] | string;
  detectedAt?: string;
  createdAt?: string;
  [key: string]: unknown;
}
export interface FingerprintCatalogInfo {
  version: string;
  sha256: string;
  ruleCount: number;
  source?: "BUILTIN" | "MANAGED" | "EXTERNAL";
}
export interface FingerprintRule {
  id: string;
  name: string;
  category?: string;
  confidence: number;
  headers?: Record<string, string[]>;
  body?: string[];
  cookies?: string[];
  title?: string[];
  header?: string[];
  faviconHash?: string[];
  faviconMd5?: string[];
}
export interface FingerprintRuleEditResult {
  catalog: FingerprintCatalogInfo;
  rule: FingerprintRule;
}
export interface SafePocRecommendation {
  vulnerabilityCode: string;
  templateId?: string;
  name: string;
  severity: string;
  templatePath?: string;
  sha256?: string;
  verificationStatus?: string;
  executionPolicy?: string;
}
export type ReconMode = "PASSIVE" | "ACTIVE";
export interface DiscoveredPath {
  id: number;
  projectId: number;
  targetId: number;
  url: string;
  path?: string;
  method?: string;
  source?: string;
  statusCode?: number;
  responseBytes?: number;
  note?: string;
  discoveredAt?: string;
}
export interface ReconEvidence {
  source?: string;
  type?: string;
  value?: string;
  detail?: string;
  collectedAt?: string;
  [key: string]: unknown;
}
export interface ReconResult {
  id?: number;
  projectId: number;
  targetId: number;
  targetValue?: string;
  mode?: ReconMode | string;
  domains?: unknown[];
  subdomains?: unknown[];
  webPaths?: string | unknown[];
  dnsRecords?: unknown[];
  ipAddresses?: unknown[];
  servers?: unknown[];
  certificates?: unknown[];
  sameSubnetHosts?: unknown[];
  rootDomain?: string;
  ipInformation?: string | Record<string, unknown> | unknown[];
  tlsInformation?: string | Record<string, unknown> | unknown[];
  httpInformation?: string | Record<string, unknown> | unknown[];
  networkInformation?: string | Record<string, unknown> | unknown[];
  registrationInformation?: string | Record<string, unknown> | unknown[];
  geolocationInformation?: string | Record<string, unknown> | unknown[];
  sourceEvidence?: string | ReconEvidence[];
  activeNetworkProbe?: boolean;
  collectedAt?: string;
  evidence?: ReconEvidence[];
  startedAt?: string;
  completedAt?: string;
  createdAt?: string;
  [key: string]: unknown;
}
export interface IcpBatchResult {
  targetId: number;
  domain: string;
  status: string;
  reason?: string;
  data: Record<string, unknown>;
}

export interface SubdomainDictionaryView {
  source: string;
  wordCount: number;
}

export interface SubdomainDictionaryWordPage {
  words: string[];
  page: number;
  size: number;
  total: number;
}

export interface SubdomainDictionaryImportResult {
  imported: number;
  invalid: number;
  duplicates: number;
  issues: string[];
}

export interface SubdomainDictionaryUpdateResult {
  view: SubdomainDictionaryView;
  added: number;
  removed: number;
  missing: string[];
}

export interface VulnerabilityCatalogSyncResult {
  status: string;
  templatesPath: string;
  sourceVersion: string;
  discovered: number;
  imported: number;
  updated: number;
  unchanged: number;
  invalid: number;
  deactivated: number;
  knownExploited: number;
  completedAt: string;
  warnings: string[];
}

export interface MsfModuleItem {
  modulePath: string;
  name: string;
  rank: string;
  description: string;
}

export interface MsfModuleCategory {
  category: string;
  label: string;
  modules: MsfModuleItem[];
}

export interface MsfModuleCatalog {
  available: boolean;
  categories: MsfModuleCategory[];
}

export interface MsfModuleOption {
  name: string;
  type: string;
  required: boolean;
  defaultValue: string;
  description: string;
}

export interface ScannerPocCatalogSyncResult {
  status: string;
  sourceType: "AFROG" | "XRAY" | "MSF";
  pocsPath: string;
  sourceVersion: string;
  discovered: number;
  imported: number;
  updated: number;
  unchanged: number;
  invalid: number;
  deactivated: number;
  completedAt: string;
  warnings: string[];
}

export interface VulnerabilityCatalogStats {
  total: number;
  builtin: number;
  nuclei: number;
  afrog: number;
  xray: number;
  msf: number;
  knownExploited: number;
  safeToScan: number;
  templatesAvailable: boolean;
  syncing: boolean;
  lastSync?: VulnerabilityCatalogSyncResult;
  afrogPocsAvailable: boolean;
  xrayPocsAvailable: boolean;
  afrogSyncing: boolean;
  xraySyncing: boolean;
  lastAfrogSync?: ScannerPocCatalogSyncResult;
  lastXraySync?: ScannerPocCatalogSyncResult;
  msfModulesAvailable: number;
  msfSyncing: boolean;
  lastMsfSync?: ScannerPocCatalogSyncResult;
}

export interface CatalogSyncProgress {
  source: "NUCLEI" | "AFROG" | "XRAY" | "MSF";
  stage:
    | "IDLE"
    | "PREPARING"
    | "DISCOVERING"
    | "IMPORTING"
    | "FINALIZING"
    | "COMPLETED"
    | "FAILED"
    | "RUNNING";
  processed: number;
  total: number;
  message: string;
  startedAt: string;
  updatedAt: string;
  active: boolean;
}

export interface VulnerabilityCatalogClearResult {
  removedDefinitions: number;
  deletedPaths: string[];
  missingPaths: string[];
}

/** Project-scoped records returned by the report summary endpoint.  Keeping the
 * shape here lets the project detail page render the same authoritative data as
 * the generated report instead of trying to infer project membership client-side. */
export interface ProjectTaskRecord {
  id: number;
  projectId: number;
  targetId: number;
  toolCode: string;
  ruleCode?: string;
  vulnerabilityCode?: string;
  workflowRunId?: number;
  workflowDigest?: string;
  workflowNodeId?: string;
  nodeRunId?: string;
  workflowGroup?: number;
  dependencyTaskIds?: string;
  status: string;
  progress: number;
  progressDeterminate?: boolean;
  progressCompleted?: number;
  progressTotal?: number;
  progressMessage?: string;
  progressUpdatedAt?: string;
  requestJson?: string;
  resultJson?: string;
  executionLog?: string;
  errorMessage?: string;
  terminationReason?: string;
  timeoutAt?: string;
  queueEnteredAt?: string;
  queueStartedAt?: string;
  targetSnapshotJson?: string;
  allowedPortsSnapshot?: string;
  authorizationStatementSnapshot?: string;
  authorizationValidFromSnapshot?: string;
  authorizationExpiresAtSnapshot?: string;
  toolVersionSnapshot?: string;
  ruleVersionSnapshot?: string;
  nucleiTemplateHashSnapshot?: string;
  authorizationSnapshotHash?: string;
  snapshotCapturedAt?: string;
  sourceTaskId?: number;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
}

/**
 * Structured output emitted by observation-only asset tools.  Port discovery
 * deliberately stays separate from vulnerability findings: an open service
 * is an exposure observation until independent evidence (for example an
 * unauthorised access condition or a verified vulnerable version) is present.
 * The index signature keeps the client tolerant of older task result payloads.
 */
export interface OpenPortObservation {
  port: number;
  protocol?: string;
  state?: string;
  service?: string;
  product?: string;
  version?: string;
  extraInfo?: string;
  assessmentType?: string;
  vulnerability?: boolean;
  note?: string;
  [key: string]: unknown;
}

export interface AssetObservationResultData {
  host?: string;
  openPorts?: Array<number | OpenPortObservation | Record<string, unknown>>;
  states?: Record<string, string>;
  assessmentType?: string;
  observationOnly?: boolean;
  vulnerability?: boolean;
  note?: string;
  requestedPorts?: string;
  requestedPortCount?: number;
  rawSummary?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface TaskExecutionResultPayload {
  summary?: string;
  data?: AssetObservationResultData | Record<string, unknown>;
  findings?: unknown[];
  assessmentType?: string;
  observationOnly?: boolean;
  vulnerability?: boolean;
  [key: string]: unknown;
}

export interface TaskProgressEvent {
  taskId: number;
  projectId?: number;
  targetId?: number;
  toolCode?: string;
  status?: string;
  progress?: number;
  progressDeterminate?: boolean;
  progressCompleted?: number;
  progressTotal?: number;
  progressMessage?: string;
  progressUpdatedAt?: string;
  logLine?: string;
  errorMessage?: string;
  terminationReason?: string;
  timeoutAt?: string;
  startedAt?: string;
  finishedAt?: string;
  emittedAt?: string;
  workflowNodeId?: string;
  nodeRunId?: string;
  dependsOnTaskIds?: number[];
}

export interface ProjectFindingRecord {
  id: number;
  taskId: number;
  targetId: number;
  projectId?: number;
  title: string;  severity: string;
  status: string;
  sourceTool: string;
  ruleCode?: string;
  vulnerabilityCode?: string;
  description: string;
  evidence: string;
  remediation: string;
  createdAt: string;
}

/** One step's verdict from the semantic judge. */
export interface JudgeStepVerdict {
  workflowNodeId?: string | null;
  toolCode: string;
  /** true only when the judge positively cleared this step. */
  allow: boolean;
  behaviour: string;
  risk: "SAFE" | "CAUTION" | "HIGH" | "CRITICAL" | string;
  confidence: number;
  summary: string;
  degraded: boolean;
  degradedReason?: string;
}

/**
 * The judge's verdict document for a whole plan.
 *
 * `degraded` means the judge could not reach a trustworthy answer (timeout, provider error,
 * low confidence). Callers must treat degraded exactly like "not cleared" — never as approval.
 */
export interface JudgeVerdictDocument {
  degraded: boolean;
  steps: JudgeStepVerdict[];
  worstRisk: string;
  requiresHumanReview: boolean;
  headline?: string;
  degradedReason?: string;
}

export interface AiApprovalPlanDetail {
  targetId: number;
  plan: Omit<AiPlan, "targetId" | "objective">;
  status: string;
  dispatch: AiDispatch | null;
  /** Raw JSON string of the judge verdict, or null on legacy tickets. */
  judge?: string | null;
}

export interface ProjectApproval {
  id: number;
  projectId: number;
  action: string;
  status: string;
  requestedBy?: string;
  initiatedBy?: string;
  dispatched?: boolean;
  approvedBy?: string;
  comment?: string;
  authorizationSnapshotHash?: string;
  createdAt: string;
  decidedAt?: string;
}

/**
 * A server-approved, project-scoped security action.  The category is kept as
 * a closed union because the API deliberately exposes an allow-list of safe
 * action types; the UI must never turn this into an arbitrary command runner.
 */
export type SecurityActionCategory =
  | "VULNERABILITY_VALIDATION"
  | "CONTROLLED_EXPLOITATION"
  | "PRIVILEGE_VALIDATION"
  | "INTERNAL_ASSESSMENT"
  | "PERSISTENCE_VALIDATION";

export type SecurityActionStatus =
  | "PENDING_APPROVAL"
  | "APPROVED"
  | "REJECTED"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "ROLLED_BACK"
  | string;

export interface SecurityAction {
  id: number;
  projectId: number;
  targetId: number;
  findingId?: number;
  category: SecurityActionCategory | string;
  title: string;
  purpose: string;
  riskLevel: string;
  nonDestructive: boolean;
  lateralMovement: boolean;
  executionPlan: string;
  rollbackPlan: string;
  windowStart: string;
  windowEnd: string;
  status: SecurityActionStatus;
  requestedBy: string;
  approvedBy?: string;
  approvedAt?: string;
  startedAt?: string;
  finishedAt?: string;
  terminationReason?: string;
  evidence?: string;
  rollbackEvidence?: string;
  createdAt: string;
}

export interface CreateSecurityActionPayload {
  targetId: number;
  findingId?: number;
  category: SecurityActionCategory;
  title: string;
  purpose: string;
  riskLevel: string;
  nonDestructive: true;
  lateralMovement: false;
  executionPlan: string;
  rollbackPlan: string;
  windowStart: string;
  windowEnd: string;
}

export interface SecurityActionDecisionPayload {
  decision: "APPROVED" | "REJECTED";
  comment?: string;
}

export interface SecurityActionCompletePayload {
  evidence?: string;
  terminationReason?: string;
}

export interface SecurityActionRollbackPayload {
  evidence?: string;
  reason?: string;
}

export interface AuditLogRecord {
  id: number;
  action: string;
  resourceType: string;
  resourceId?: string;
  operator?: string;
  operatorRoles?: string;
  sourceIp?: string;
  requestId?: string;
  relatedTaskId?: number;
  authorizationSnapshotHash?: string;
  detail?: string;
  result: string;
  createdAt: string;
}

export interface ClearBusinessDataResponse {
  clearedAt: string;
  deletedRecords: number;
  auditLogRetained: boolean;
}

export interface ProjectReportSummary {
  project: AssessmentProject;
  targets: ProjectTarget[];
  vulnerabilityDiscovery: ProjectTaskRecord[];
  findings: ProjectFindingRecord[];
  severityCounts: Record<string, number>;
  informationCollection?: unknown[];
  fingerprintAndWafEvidence?: unknown[];
  approvals: ProjectApproval[];
  verification?: { retestedFindings: number; awaitingRetest: number };
  controlledPostExploitation?: {
    recordedTasks: number;
    safetyBoundary: string;
  };
  approvalAndAudit?: {
    totalApprovals: number;
    approved: number;
    rejected: number;
  };
  generatedAt: string;
}

export interface PostScanPathStep {
  id: string;
  title: string;
  phase: string;
  riskLevel: string;
  reason: string;
  prerequisites: string[];
  expectedEvidence: string;
  impact: string;
  automated: boolean;
  toolCode?: string;
  parameters: Record<string, unknown>;
  blockedReason?: string;
}

export interface PostScanHypothesis {
  id: string;
  title: string;
  riskLevel: string;
  confidence: string;
  goal: string;
  prerequisites: string[];
  evidenceBasis: string;
  limitations: string[];
  stopConditions: string[];
}

export interface PostScanPath {
  id: number;
  targetId: number;
  projectId: number;
  findingIds: number[];  provider: string;
  model: string;
  summary: string;
  analysis: string;
  status: string;
  expiresAt: string;
  requiresConfirmation: boolean;
  paths: PostScanHypothesis[];
  steps: PostScanPathStep[];
  taskIds: number[];
}

export interface DetectionRule {
  id: number;
  ruleCode: string;
  vulnerabilityCode: string;
  name: string;
  toolCode: string;
  targetType: string;
  riskLevel: string;
  enabled: boolean;
  sourceType?: string;
  sourceName?: string;
}

export const endpoints = {
  // A cold desktop scan launches several local version commands and can legitimately take
  // longer than the normal API timeout. Keep the larger timeout scoped to this endpoint.
  health: () =>
    api.get<{ status: string }>("/system/health", { timeout: 3_000 }),
  dependencies: (refresh = false) =>
    api.get<SystemDependenciesResponse>("/system/dependencies", {
      params: refresh ? { refresh: true } : undefined,
      timeout: 45_000,
    }),
  dashboard: () => api.get("/dashboard/summary"),
  clearBusinessData: () =>
    api.delete<ClearBusinessDataResponse>("/settings/data", {
      data: { confirmation: "永久清空" },
      timeout: 30_000,
    }),
  changePassword: (payload: { currentPassword: string; newPassword: string }) =>
    api.post("/auth/change-password", payload),
  targets: () => api.get<Target[]>("/targets"),
  createTarget: (payload: Omit<Target, "id">) =>
    api.post<Target>("/targets", payload),
  updateTarget: (id: number, payload: Omit<Target, "id">) =>
    api.put<Target>(`/targets/${id}`, payload),
  deleteTarget: (id: number) => api.delete(`/targets/${id}`),
  createPlan: (payload: { targetId: number; prompt: string }) =>
    api.post<Omit<AiPlan, "targetId" | "objective">>("/ai/plans", payload, {
      timeout: 210000,
    }),
  dispatchAi: (payload: AiAgentRequestPayload) =>
    api.post<AiDispatch>("/ai/dispatches", payload, { timeout: 210000 }),
  runAgent: (payload: AiAgentRequestPayload) =>
    api.post<AiAgentResponsePayload>("/ai/agent", payload, { timeout: 210000 }),
  // 删除会话在后端还要尽力清理 AI Runtime 的索引记忆，可能明显慢于普通请求；
  // 未显式设置时会被 axios 默认超时（10 秒）掐断，表现为请求被中止、
  // 会话数不减少（桌面 K-17 稳定复现）。这里给它一个更宽的超时。
  clearAgentSession: (sessionId: string) =>
    api.delete<{ sessionId: string; cleared: boolean }>(
      `/ai/agent/sessions/${encodeURIComponent(sessionId)}`,
      { timeout: 45_000 },
    ),
  // 停止本会话的自动续接：只取消尚未执行的续接记录，已完成的任务不受影响。
  stopAgentContinuation: (sessionId: string) =>
    api.post<{ sessionId: string; cancelled: number }>(
      `/ai/agent/sessions/${encodeURIComponent(sessionId)}/continuation/stop`,
      undefined,
      { timeout: 20_000 },
    ),
  listConversations: () => api.get<any[]>("/ai/conversations", { timeout: 15_000 }),
  saveConversation: (sessionId: string, payload: any) =>
    api.put(`/ai/conversations/${encodeURIComponent(sessionId)}`, payload, { timeout: 20_000 }),
  deleteConversation: (sessionId: string) =>
    api.delete(`/ai/conversations/${encodeURIComponent(sessionId)}`, { timeout: 30_000 }),
  clearAllConversations: () =>
    api.delete("/ai/conversations", { timeout: 30_000 }),
  answerAi: (payload: {
    projectId: number;
    targetId: number;
    prompt: string;
    taskIds: number[];
  }) => api.post<AiAnswer>("/ai/answers", payload, { timeout: 210000 }),
  createTask: (payload: {
    projectId?: number;
    targetId: number;
    toolCode: string;
    parameters?: Record<string, unknown>;
  }) => api.post("/tasks", payload),
  retryTask: (id: number, idempotencyKey?: string) => api.post(`/tasks/${id}/retry`, undefined,
    idempotencyKey ? { headers: { "Idempotency-Key": idempotencyKey } } : undefined),
  cancelTask: (id: number) => api.post(`/tasks/${id}/cancel`),
  workflowRuns: (projectId: number) =>
    api.get<WorkflowRunSummary[]>("/workflow-runs", { params: { projectId } }),
  workflowRun: (id: number) =>
    api.get<WorkflowRunDetail>(`/workflow-runs/${id}`),
  preflightWorkflowRun: (payload: {
    projectId: number;
    targetId: number;
    workflowId?: string;
    workflowRevision?: number;
    workflowDigest?: string;
  }) =>
    api.post<WorkflowRunPreflight>("/workflow-runs/preflight", payload, {
      timeout: 180_000,
    }),
  startWorkflowRun: (payload: {
    projectId: number;
    targetId: number;
    workflowId: string;
    workflowRevision: number;
    workflowDigest: string;
    approvedNodeIds?: string[];
    skippedNodeIds?: string[];
  }) =>
    api.post<WorkflowRunDetail>("/workflow-runs", payload, {
      timeout: 180_000,
    }),
  stopWorkflowRun: (id: number) =>
    api.post<WorkflowRunDetail>(`/workflow-runs/${id}/stop`, undefined, {
      timeout: 180_000,
    }),
  clearWorkflowRun: (id: number) => api.delete(`/workflow-runs/${id}`),
  vulnerabilities: (
    params: {
      page?: number;
      size?: number;
      query?: string;
      severity?: string;
      source?: string;
      year?: string;
      knownExploited?: boolean;
      scanSafety?: string;
      sort?: string;
    } = {},
  ) =>
    api.get<PageResponse<VulnerabilityDefinition>>("/vulnerabilities", {
      params,
    }),
  vulnerabilityStats: () =>
    api.get<VulnerabilityCatalogStats>("/vulnerabilities/stats"),
  vulnerabilitySyncStatus: () =>
    api.get<CatalogSyncProgress[]>("/vulnerabilities/sync/status"),
  clearVulnerabilityCatalog: () =>
    api.delete<VulnerabilityCatalogClearResult>("/vulnerabilities/catalog", {
      timeout: 120_000,
    }),
  syncNucleiCatalog: () =>
    api.post<VulnerabilityCatalogSyncResult>(
      "/vulnerabilities/sync/nuclei",
      undefined,
      { timeout: 10 * 60_000 },
    ),
  syncAfrogCatalog: () =>
    api.post<ScannerPocCatalogSyncResult>(
      "/vulnerabilities/sync/afrog",
      undefined,
      { timeout: 10 * 60_000 },
    ),
  syncXrayCatalog: () =>
    api.post<ScannerPocCatalogSyncResult>(
      "/vulnerabilities/sync/xray",
      undefined,
      { timeout: 10 * 60_000 },
    ),
  syncMsfCatalog: () =>
    api.post<ScannerPocCatalogSyncResult>(
      "/vulnerabilities/sync/msf",
      undefined,
      { timeout: 10 * 60_000 },
    ),
  getMsfModules: () =>
    api.get<MsfModuleCatalog>("/msf/modules", { timeout: 120_000 }),
  getMsfModuleOptions: (module: string) =>
    api.get<{ options: MsfModuleOption[] }>("/msf/modules/options", {
      params: { module },
      timeout: 120_000,
    }),
  createPostScanPath: (payload: {
    projectId: number;
    targetId: number;
    findingIds: number[];
    objective?: string;
  }) =>    api.post<PostScanPath>("/post-scan-paths/plans", payload, {
      timeout: 210_000,
    }),
  confirmPostScanPath: (
    id: number,
    payload: { acknowledged: boolean; selectedStepIds: string[] },
  ) => api.post<PostScanPath>(`/post-scan-paths/${id}/confirm`, payload),
  postScanPath: (id: number) => api.get<PostScanPath>(`/post-scan-paths/${id}`),
  detectionRules: () => api.get<DetectionRule[]>("/vulnerabilities/rules"),
  startActiveScan: (payload: {
    projectId: number;
    targetId: number;
    ruleCodes?: string[];
    pocCodes?: string[];
    allPocSources?: Array<"NUCLEI" | "AFROG" | "XRAY">;
    ports?: string;
    vulnModes?: Record<string, string>;
    toolParams?: Record<string, Record<string, string | number | boolean>>;
    paths?: string[];
  }) =>
        api.post("/active-scans", payload, {
          // 全量 PoC 扫描需在后台校验/加载所有 PoC 文件，创建耗时可能远超默认超时
          timeout: 120_000,
        }),
  tasks: () => api.get<ProjectTaskRecord[]>("/tasks"),
  taskControlStatus: () => api.get<TaskControlStatus>("/tasks/control/status"),
  taskControlLimits: () => api.get<TaskExecutionLimitView>("/tasks/control/limits"),
  updateTaskControlLimits: (maxConcurrentTasks: number) =>
    api.put<TaskExecutionLimitView>("/tasks/control/limits", { maxConcurrentTasks }),
  task: (id: number) => api.get<ProjectTaskRecord>(`/tasks/${id}`),
  findings: (
    page = 0,
    size = 20,
    query = "",
    targetId?: number,
    severity?: string,
    status?: string,
    category?: string,
    sort?: string,
    taskId?: number,
  ) =>
    api.get<PageResponse<ProjectFindingRecord>>("/findings", {
      params: {
        page,
        size,
        query: query || undefined,
        targetId: targetId || undefined,
        severity: severity || undefined,
        status: status || undefined,
        category: category || undefined,
        sort: sort || undefined,
        taskId: taskId || undefined,
      },
    }),
  updateFindingStatus: (id: number, status: string) =>
    api.put(`/findings/${id}/status`, { status }),
  deleteFinding: (id: number) => api.delete(`/findings/${id}`),
  clearFindings: () => api.delete("/findings"),
  retestFinding: (id: number) => api.post(`/regression/findings/${id}/retest`),
  scanDiff: (baselineTaskId: number, currentTaskId: number) =>
    api.get<ScanDiff>("/regression/scan-diff", {
      params: { baselineTaskId, currentTaskId },
    }),
  downloadReport: (taskId: number) =>
    api.get(`/reports/tasks/${taskId}/download`, {
      responseType: "blob",
      timeout: 120_000,
    }),
  downloadTargetReportPdf: (targetId: number) =>
    api.get(`/reports/projects/targets/${targetId}.pdf`, {
      responseType: "blob",
      timeout: 120_000,
    }),
  scanSchedules: () => api.get<ScanSchedule[]>("/scan-schedules"),
  createScanSchedule: (payload: {
    projectId: number;
    targetId: number;
    toolCode: string;
    parameters?: Record<string, unknown>;
    cronExpression?: string;
    intervalSeconds?: number;
    enabled?: boolean;
  }) => api.post<ScanSchedule>("/scan-schedules", payload),
  enableScanSchedule: (id: number) =>
    api.post<ScanSchedule>(`/scan-schedules/${id}/enable`),
  disableScanSchedule: (id: number) =>
    api.post<ScanSchedule>(`/scan-schedules/${id}/disable`),
  deleteScanSchedule: (id: number) => api.delete(`/scan-schedules/${id}`),
  audits: (page = 0, size = 20, projectId?: number) =>
    api.get<PageResponse<AuditLogRecord>>("/audits", {
      params: { page, size, projectId },
    }),
  agentGraph: () => api.get<WorkflowGraph>("/ai/agent/graph"),
  getWorkflowSpec: (projectId: number) =>
    api.get<WorkflowSpecV2>("/ai/workflow", { params: { projectId } }),
  saveWorkflowSpec: (projectId: number, spec: WorkflowSpecV2) =>
    api.put<WorkflowSpecV2>("/ai/workflow", spec, { params: { projectId } }),

  saveMemory: (payload: {
    projectId: number;
    targetId: number;
    conversationId?: string;
    prompt: string;
    answer: string;
  }) => api.post<{ id: string; title: string }>("/ai/memories", payload),
  listMemories: (projectId: number) =>
    api.get<MemoryDoc[]>("/ai/memories", { params: { projectId } }),
  deleteMemory: (projectId: number, docId: string) =>
    api.delete(`/ai/memories/${docId}`, { params: { projectId } }),
  clearMemories: (projectId: number) =>
    api.delete<{ deleted: number; projectId: number }>("/ai/memories", {
      params: { projectId },
    }),
  projects: () => api.get<AssessmentProject[]>("/projects"),
  project: (id: number) => api.get<AssessmentProject>(`/projects/${id}`),
  createProject: (payload: {
    name: string;
    description?: string;
    authorizationStatement: string;
    authorizationValidFrom: string;
    authorizationExpiresAt: string;
    owner: string;
  }) => api.post<AssessmentProject>("/projects", payload),
  updateProject: (id: number, payload: Partial<{
    name: string;
    description?: string;
    authorizationStatement: string;
    authorizationValidFrom: string;
    authorizationExpiresAt: string;
    owner: string;
  }>) => api.put<AssessmentProject>(`/projects/${id}`, payload),
  updateProjectStatus: (id: number, status: string) =>
    api.post<AssessmentProject>(`/projects/${id}/status`, { status }),
  projectSummary: (id: number) =>
    api.get<ProjectSummary>(`/projects/${id}/summary`),
  projectTargets: (id: number) =>
    api.get<ProjectTarget[]>(`/projects/${id}/targets`),
  addProjectTarget: (id: number, targetId: number) =>
    api.post<ProjectTarget>(`/projects/${id}/targets/${targetId}`),
  removeProjectTarget: (id: number, targetId: number) =>
    api.delete(`/projects/${id}/targets/${targetId}`),
  projectApprovals: (id: number) =>
    api.get<ProjectApproval[]>(`/projects/${id}/approvals`),
  requestProjectApproval: (
    id: number,
    payload: {
      action: string;
      comment?: string;
      authorizationSnapshotHash?: string;
    },
  ) => api.post<ProjectApproval>(`/projects/${id}/approvals`, payload),
  decideProjectApproval: (
    projectId: number,
    approvalId: number,
    payload: { status: string; comment?: string; stepOverrides?: Array<Record<string, unknown>> },
  ) =>
    api.post<ProjectApproval>(
      `/projects/${projectId}/approvals/${approvalId}/decision`,
      payload,
    ),
  projectAiApprovalPlan: (projectId: number, approvalId: number) =>
    api.get<AiApprovalPlanDetail>(`/projects/${projectId}/approvals/${approvalId}/plan`),
  resumeProjectAiApproval: (projectId: number, approvalId: number) =>
    api.post<AiDispatch>(`/projects/${projectId}/approvals/${approvalId}/execute`, undefined, { timeout: 210_000 }),
  securityActions: (projectId: number) =>
    api.get<SecurityAction[]>(`/projects/${projectId}/security-actions`),
  createSecurityAction: (
    projectId: number,
    payload: CreateSecurityActionPayload,
  ) =>
    api.post<SecurityAction>(
      `/projects/${projectId}/security-actions`,
      payload,
    ),
  decideSecurityAction: (
    projectId: number,
    actionId: number,
    payload: SecurityActionDecisionPayload,
  ) =>
    api.post<SecurityAction>(
      `/projects/${projectId}/security-actions/${actionId}/decision`,
      payload,
    ),
  startSecurityAction: (projectId: number, actionId: number) =>
    api.post<SecurityAction>(
      `/projects/${projectId}/security-actions/${actionId}/start`,
    ),
  completeSecurityAction: (
    projectId: number,
    actionId: number,
    payload: SecurityActionCompletePayload,
  ) =>
    api.post<SecurityAction>(
      `/projects/${projectId}/security-actions/${actionId}/complete`,
      payload,
    ),
  rollbackSecurityAction: (
    projectId: number,
    actionId: number,
    payload: SecurityActionRollbackPayload,
  ) =>
    api.post<SecurityAction>(
      `/projects/${projectId}/security-actions/${actionId}/rollback`,
      payload,
    ),
  projectReportSummary: (id: number) =>
    api.get<ProjectReportSummary>(`/reports/projects/${id}/summary`, {
      timeout: 120_000,
    }),
  downloadProjectReportPdf: (projectId: number) =>
    api.get(`/reports/projects/${projectId}.pdf`, {
      responseType: "blob",
      timeout: 120000,
    }),
  downloadProjectReportHtml: (projectId: number) =>
    api.get<string>(`/reports/projects/${projectId}.html`, {
      responseType: "text",
      timeout: 120000,
    }),
  downloadTargetReportHtml: (targetId: number) =>
    api.get<string>(`/reports/projects/targets/${targetId}.html`, {
      responseType: "text",
      timeout: 120000,
    }),
  fingerprintCatalog: () =>
    api.get<FingerprintCatalogInfo>("/fingerprints/catalog"),
  reloadFingerprintCatalog: () =>
    api.post<FingerprintCatalogInfo>("/fingerprints/catalog/reload"),
  updateFingerprintCatalog: (catalogBytes: ArrayBuffer) =>
    api.put<FingerprintCatalogInfo>("/fingerprints/catalog", catalogBytes, {
      headers: { "Content-Type": "application/json" },
      timeout: 30_000,
      transformRequest: [(data) => data],
    }),
  fingerprintRules: () => api.get<FingerprintRule[]>("/fingerprints/rules"),
  validateFingerprintRule: (rule: FingerprintRule) =>
    api.post<Record<string, string>>("/fingerprints/rules/validate", rule),
  addFingerprintRule: (rule: FingerprintRule) =>
    api.post<FingerprintCatalogInfo>("/fingerprints/rules", rule, {
      timeout: 30_000,
    }),
  updateFingerprintRule: (ruleId: string, rule: FingerprintRule) =>
    api.put<FingerprintRuleEditResult>(`/fingerprints/rules/${ruleId}`, rule, {
      timeout: 30_000,
    }),
  deleteFingerprintRule: (ruleId: string) =>
    api.delete<FingerprintCatalogInfo>(`/fingerprints/rules/${ruleId}`, {
      timeout: 30_000,
    }),
  pocRecommendations: (fingerprintIds: string[]) =>
    api.post<SafePocRecommendation[]>("/fingerprints/poc-recommendations", {
      fingerprintIds,
    }),
  probeProjectTarget: (projectId: number, targetId: number) =>
    api.post<DiscoveryResult>(
      `/projects/${projectId}/discovery/probe`,
      { targetId },
      { timeout: 120_000 },
    ),
  projectDiscoveryResults: (projectId: number, targetId?: number) =>
    api.get<DiscoveryResult[]>(`/projects/${projectId}/discovery/results`, {
      params: targetId ? { targetId } : undefined,
    }),
  deleteDiscoveryResult: (projectId: number, id: number) =>
    api.delete<void>(`/projects/${projectId}/discovery/results/${id}`),
  collectProjectRecon: (
    projectId: number,
    payload: {
      targetId: number;
      mode: ReconMode;
      includeSameSubnet?: boolean;
      includeHttp?: boolean;
      includeTls?: boolean;
      enumerateSubdomains?: boolean;
      subdomainWords?: string[];
      enumeratePaths?: boolean;
      pathWords?: string[];
      pathDictionaryId?: string;
      pathConcurrency?: number;
      crawlSite?: boolean;
      aggregateProxyPaths?: boolean;
      activeNetworkProbe?: boolean;
    },
  ) =>
    api.post<ReconResult>(`/projects/${projectId}/recon/collect`, payload, {
      // 主动信息收集是同步请求，包含目录枚举（并发）、站点爬取和参数探测。
      // 用大字典（如 dirbuster 8 万条）或目标响应较慢时，180 秒会误判超时并丢弃已完成的结果；
      // 后端已对参数探测设独立时间预算，这里把总超时放宽到 10 分钟。
      timeout: 600_000,
    }),
  targetDiscoveredPaths: (targetId: number) =>
    api.get<DiscoveredPath[]>(`/targets/${targetId}/discovered-paths`),
  projectReconResults: (projectId: number, targetId?: number) =>
    api.get<ReconResult[]>(`/projects/${projectId}/recon/results`, {
      params: targetId ? { targetId } : undefined,
    }),
  projectDiscoveredPaths: (projectId: number, targetId?: number) =>
    api.get<DiscoveredPath[]>(`/projects/${projectId}/recon/paths`, {
      params: targetId ? { targetId } : undefined,
    }),
  subdomainDictionary: () =>
    api.get<SubdomainDictionaryView>("/recon/subdomain-dictionary"),
  subdomainDictionaryWords: (
    query = "",
    page = 1,
    size = 30,
  ) =>
    api.get<SubdomainDictionaryWordPage>("/recon/subdomain-dictionary/words", {
      params: { query: query || undefined, page, size },
    }),
  validateSubdomainWords: (words: string[]) =>
    api.post<string[]>("/recon/subdomain-dictionary/validate", { words }),
  importSubdomainWords: (text: string) =>
    api.post<SubdomainDictionaryImportResult>(
      "/recon/subdomain-dictionary/import",
      { text },
      { timeout: 60_000 },
    ),
  updateSubdomainDictionary: (
    additions: string[],
    removals: string[],
  ) =>
    api.post<SubdomainDictionaryUpdateResult>(
      "/recon/subdomain-dictionary/update",
      { additions, removals },
      { timeout: 60_000 },
    ),
  pathDictionary: () =>
    api.get<SubdomainDictionaryView>("/recon/path-dictionary"),
  pathDictionaryLibrary: () =>
    api.get<{
      defaultDictionaryId: string;
      dictionaries: Array<{
        id: string;
        displayName: string;
        source: string;
        entryCount: number;
        description: string;
      }>;
    }>("/recon/path-dictionary/library"),
  pathDictionaryWords: (
    query = "",
    page = 1,
    size = 30,
  ) =>
    api.get<SubdomainDictionaryWordPage>("/recon/path-dictionary/words", {
      params: { query: query || undefined, page, size },
    }),
  validatePathWords: (words: string[]) =>
    api.post<string[]>("/recon/path-dictionary/validate", { words }),
  importPathWords: (text: string) =>
    api.post<SubdomainDictionaryImportResult>(
      "/recon/path-dictionary/import",
      { text },
      { timeout: 60_000 },
    ),
  updatePathDictionary: (
    additions: string[],
    removals: string[],
  ) =>
    api.post<SubdomainDictionaryUpdateResult>(
      "/recon/path-dictionary/update",
      { additions, removals },
      { timeout: 60_000 },
    ),
  syncTrafficAssets: () =>
    api.post<{ synced: number }>("/traffic/assets/sync"),
  projectIcpBatch: (projectId: number, targetIds: number[]) =>
    api.post<IcpBatchResult[]>(
      `/projects/${projectId}/recon/icp/batch`,
      { targetIds },
      { timeout: 120_000 },
    ),
  icpStartCaptcha: (projectId: number, targetId: number) =>
    api.post<{
      challengeId: string;
      domain: string;
      image: string;
      characterStrip: string;
      message: string;
    }>(`/projects/${projectId}/recon/icp/captcha`, { targetId }),
  icpVerifyCaptcha: (
    projectId: number,
    targetId: number,
    challengeId: string,
    points: { x: number; y: number }[],
  ) =>
    api.post<{
      domain: string;
      status: string;
      reason?: string;
      records?: Array<Record<string, unknown>>;
      total?: number;
    }>(`/projects/${projectId}/recon/icp/captcha/verify`, {
      targetId,
      challengeId,
      points,
    }),
  icpBrowserCapture: (
    projectId: number,
    targetId: number,
    records: Array<Record<string, unknown>>,
  ) =>
    api.post<{
      domain: string;
      status: string;
      source?: string;
      reason?: string;
      records?: Array<Record<string, unknown>>;
      total?: number;
    }>(`/projects/${projectId}/recon/icp/browser/capture`, {
      targetId,
      records,
    }),
};

async function streamTaskEventPath(
  path: string,
  onEvent: (value: TaskProgressEvent) => void,
  signal: AbortSignal,
) {
  const token = readAuthToken();
  const response = await apiFetch(apiUrl(path), {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      Accept: "text/event-stream",
    },
    signal,
  });
  if (!response.ok || !response.body) {
    throw new Error(`任务事件流连接失败：HTTP ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    buffer = buffer.replace(/\r\n/g, "\n");
    let end: number;
    while ((end = buffer.indexOf("\n\n")) >= 0) {
      const block = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      const data = block
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trim())
        .join("\n");
      if (!data) continue;

      try {
        onEvent(JSON.parse(data));
      } catch {
        // Ignore malformed events and keep the long-lived feed connected.
      }
    }
  }
}

export async function streamTaskEvents(
  taskId: number,
  onEvent: (value: TaskProgressEvent) => void,
  signal: AbortSignal,
) {
  return streamTaskEventPath(`/tasks/${taskId}/events`, onEvent, signal);
}

export async function streamAllTaskEvents(
  onEvent: (value: TaskProgressEvent) => void,
  signal: AbortSignal,
) {
  return streamTaskEventPath("/tasks/events", onEvent, signal);
}

/** Keeps one authenticated all-task SSE feed alive until the returned disposer is called. */
export function connectTaskEventFeed(
  onEvent: (value: TaskProgressEvent) => void,
) {
  let stopped = false;
  let activeController: AbortController | undefined;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;

  const connect = async () => {
    if (stopped || !readAuthToken()) return;
    activeController = new AbortController();
    try {
      await streamAllTaskEvents(onEvent, activeController.signal);
    } catch {
      // Polling in the consuming views remains the fallback while SSE reconnects.
    }
    if (!stopped && readAuthToken())
      retryTimer = setTimeout(() => void connect(), 1_000);
  };

  void connect();
  return () => {
    stopped = true;
    activeController?.abort();
    if (retryTimer) clearTimeout(retryTimer);
  };
}

const STREAM_IDLE_TIMEOUT_MS = 90_000;

export type WorkflowSuggestStreamEvent = {
  type: string;
  phase?: string;
  message?: string;
  modelEnabled?: boolean;
  suggestion?: WorkflowSuggestion;
  index?: number;
  origin?: string;
  source?: string;
  model?: string;
  note?: string;
  count?: number;
  generatedAt?: string;
};

export async function streamWorkflowSuggestions(
  payload: {
    graph: { nodes: WorkflowGraphNodeSpec[]; edges: WorkflowGraphEdgeSpec[] };
    preset?: string;
    selectedNodeId?: string;
    focus?: string;
  },
  onEvent: (event: WorkflowSuggestStreamEvent) => void,
  signal?: AbortSignal,
) {
  const token = readAuthToken();
  const response = await apiFetch(apiUrl("/ai/workflow/suggest"), {
    method: "POST",
    headers: {
      Accept: "text/event-stream",
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(payload),
    signal,
  });
  if (!response.ok || !response.body) {
    throw new Error(`工作流建议流连接失败：HTTP ${response.status}`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    buffer = buffer.replace(/\r\n/g, "\n");
    let end: number;
    while ((end = buffer.indexOf("\n\n")) >= 0) {
      const block = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      const lines = block.split(/\n/);
      let eventName = "message";
      const dataLines: string[] = [];
      for (const line of lines) {
        if (line.startsWith("event:"))
          eventName = line.slice(6).trim() || eventName;
        else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
      }
      if (!dataLines.length) continue;
      try {
        const parsed = JSON.parse(
          dataLines.join("\n"),
        ) as WorkflowSuggestStreamEvent;
        if (!parsed.type) parsed.type = eventName;
        onEvent(parsed);
      } catch {
        /* ignore malformed */
      }
    }
  }
}

function eventPayload(value: unknown): Record<string, any> {
  if (!value || typeof value !== "object") return {};
  const source = value as Record<string, any>;
  const nested =
    source.data && typeof source.data === "object"
      ? source.data
      : source.payload && typeof source.payload === "object"
        ? source.payload
        : undefined;
  return nested ? { ...source, ...nested } : source;
}

function normalizeEventType(value: unknown, fallback?: string): string {
  const raw = String(value || fallback || "progress").trim();
  const aliases: Record<string, string> = {
    plan_created: "plan",
    plan_updated: "plan",
    planner: "plan",
    planner_progress: "plan",
    step_started: "step",
    step_updated: "step",
    step_completed: "step",
    executor: "step",
    reviewer: "step",
    authorization_guard: "step",
    engagement: "step",
    engage: "step",
    reconnaissance: "step",
    recon: "step",
    mapping: "step",
    map: "step",
    discovery: "step",
    vulnerability_discovery: "step",
    validation: "step",
    validate: "step",
    impact: "step",
    impact_assessment: "step",
    retest: "step",
    remediation: "step",
    report: "step",
    reporting: "step",
    tool_start: "tool_call",
    on_tool_start: "tool_call",
    tool_call_start: "tool_call",
    tool_end: "tool_result",
    on_tool_end: "tool_result",
    tool_call_end: "tool_result",
    approval_required: "approval",
    approval_requested: "approval",
    retrying: "retry",
    retry_requested: "retry",
    source: "citation",
    reference: "citation",
    complete: "done",
    completed: "done",
    finish: "done",
    failure: "error",
    failed: "error",
  };
  return aliases[raw.toLowerCase()] || raw;
}

const PUBLIC_NODE_STATUSES = new Set<PublicAgentNodeStatus>([
  "ROUTING",
  "RETRIEVING",
  "GROUNDED",
  "WAITING_APPROVAL",
  "EXECUTING",
  "REVIEWED",
  "FAILED",
]);

function normalizeModelUsage(value: Record<string, any>): ConversationAgentEvent["modelUsage"] | undefined {
  const integer = (key: string, max = 4_000_000_000) => {
    const number = value[key];
    return Number.isInteger(number) && number >= 0 && number <= max ? number : null;
  };
  const source = ["PROVIDER", "ESTIMATED", "MIXED", "UNAVAILABLE"].includes(value.source) ? value.source : null;
  const cache = value.cacheHitRatePermille;
  const cacheRate = cache === null ? null : integer("cacheHitRatePermille", 1000);
  const modelCalls = integer("modelCalls", 10_000);
  const smallCounts = ["providerReportedCalls", "estimatedCalls", "cacheReportedCalls"]
    .map((key) => integer(key, 10_000));
  const extraTokenCounts = ["cacheWriteTokens", "reasoningTokens", "estimatedInputTokens", "lastInputTokens"]
    .map((key) => integer(key));
  const contextSource = ["MODEL", "CONFIGURED", "DEFAULT"].includes(value.contextWindowSource)
    ? value.contextWindowSource : null;
  const estimator = typeof value.estimator === "string" && value.estimator.length <= 32 ? value.estimator : null;
  const input = integer("inputTokens"), output = integer("outputTokens"), total = integer("totalTokens");
  const cached = integer("cachedInputTokens"), window = integer("contextWindowTokens");
  const used = integer("contextWindowUsedTokens"), rate = integer("contextWindowUsagePermille", 1000);
  const peak = integer("peakInputTokens");
  if (typeof value.available !== "boolean" || !source || modelCalls === null || input === null
      || output === null || total === null || cached === null || cacheRate === undefined
      || window === null || used === null || rate === null || peak === null
      || smallCounts.some((count) => count === null) || extraTokenCounts.some((count) => count === null)
      || !contextSource || !estimator
      || typeof value.model !== "string" || value.model.length > 120) return undefined;
  return {
    available: value.available,
    source,
    model: value.model,
    modelCalls,
    inputTokens: input,
    outputTokens: output,
    totalTokens: total,
    cachedInputTokens: cached,
    cacheHitRatePermille: cacheRate,
    contextWindowTokens: window,
    contextWindowUsedTokens: used,
    contextWindowUsagePermille: rate,
    peakInputTokens: peak,
    providerReportedCalls: smallCounts[0] as number,
    estimatedCalls: smallCounts[1] as number,
    cacheReportedCalls: smallCounts[2] as number,
    cacheWriteTokens: extraTokenCounts[0] as number,
    reasoningTokens: extraTokenCounts[1] as number,
    estimatedInputTokens: extraTokenCounts[2] as number,
    lastInputTokens: extraTokenCounts[3] as number,
    contextWindowSource: contextSource as "MODEL" | "CONFIGURED" | "DEFAULT",
    estimator: estimator as string,
  };
}

function boundedNumber(value: unknown): number | undefined {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : undefined;
}

function boundedString(value: unknown, maxLength = 256): string | undefined {
  if (typeof value !== "string") return undefined;
  const text = value.trim();
  return text ? text.slice(0, maxLength) : undefined;
}

function publicNodeStatus(
  raw: Record<string, any>,
  type: string,
): PublicAgentNodeStatus {
  const explicit = String(
    raw.publicNodeStatus || raw.outerNodeStatus || raw.nodeStatus || "",
  ).toUpperCase() as PublicAgentNodeStatus;
  if (PUBLIC_NODE_STATUSES.has(explicit)) return explicit;
  const status = String(raw.status || "").toUpperCase();
  const innerStep = String(
    raw.innerStep || raw.node || raw.stage || raw.phase || "",
  ).toLowerCase();
  if (type === "error" || ["FAILED", "DENIED", "REJECTED"].includes(status))
    return "FAILED";
  if (type === "approval" || status === "APPROVAL_REQUIRED")
    return "WAITING_APPROVAL";
  if (/approval/.test(innerStep)) return "WAITING_APPROVAL";
  if (/tool|execute|dispatch/.test(innerStep)) return "EXECUTING";
  if (/review|finish|complete/.test(innerStep)) return "REVIEWED";
  if (/ground|assess|plan/.test(innerStep)) return "GROUNDED";
  if (/retrieve|rewrite|evidence/.test(innerStep)) return "RETRIEVING";
  if (/route|scope|engage/.test(innerStep)) return "ROUTING";
  if (["tool_call", "tool_result", "retry"].includes(type))
    return "EXECUTING";
  if (["review", "done"].includes(type)) return "REVIEWED";
  if (type === "plan" || type === "guard") return "GROUNDED";
  if (["evidence", "rewrite", "citation"].includes(type))
    return "RETRIEVING";
  return "ROUTING";
}

/** Normalize LangChain/LangGraph callback names and the native agent event
 * contract to one small shape consumed by the conversation store. */
export function normalizeAgentEvent(
  value: unknown,
  sseType?: string,
): AgentStreamEvent | undefined {
  const raw = eventPayload(value);
  const originalType = String(raw.type || raw.event || sseType || "")
    .trim()
    .toLowerCase();
  const type = normalizeEventType(raw.type || raw.event || raw.name, sseType);
  if (!type) return undefined;
  const step = raw.step && typeof raw.step === "object" ? raw.step : raw;
  const citationRaw = raw.citation || raw.reference || undefined;
  // Lifecycle/status events must not become fake reference chips.
  const citationCandidate =
    citationRaw && typeof citationRaw === "object"
      ? citationRaw
      : type === "citation" &&
          (raw.title || raw.name || raw.snippet || raw.text || raw.url)
        ? raw
        : undefined;
  const citation =
    citationCandidate && typeof citationCandidate === "object"
      ? ({
          id:
            citationCandidate.id ||
            citationCandidate.citationId ||
            citationCandidate.sourceId,
          title:
            citationCandidate.title ||
            citationCandidate.name ||
            citationCandidate.label,
          source:
            citationCandidate.source ||
            citationCandidate.sourceName ||
            citationCandidate.provider,
          url: citationCandidate.url || citationCandidate.href,
          summaryLength:
            boundedNumber(citationCandidate.summaryLength) ??
            String(
              citationCandidate.snippet ||
                citationCandidate.summary ||
                citationCandidate.text ||
                "",
            ).length,
          locator: citationCandidate.locator || citationCandidate.path,
        } as ConversationCitation)
      : undefined;
  const responseRaw =
    raw.response && typeof raw.response === "object" ? raw.response : undefined;
  const usageRaw = raw.modelUsage && typeof raw.modelUsage === "object" ? raw.modelUsage : responseRaw?.modelUsage;
  const modelUsage = usageRaw && typeof usageRaw === "object" ? normalizeModelUsage(usageRaw) : undefined;
  const planRaw =
    raw.plan && typeof raw.plan === "object"
      ? raw.plan
      : responseRaw?.plan && typeof responseRaw.plan === "object"
        ? responseRaw.plan
        : undefined;
  const actionRaw = (raw.actions ||
    planRaw?.actions ||
    raw.steps ||
    planRaw?.steps) as Array<Record<string, any>> | undefined;
  const steps = Array.isArray(actionRaw)
    ? actionRaw.map((step, index) => ({
        workflowNodeId:
          step.workflowNodeId || step.workflow_node_id || step.nodeId,
        nodeRunId: step.nodeRunId,
        group: boundedNumber(step.group),
        dependsOnNodeIds: Array.isArray(step.dependsOnNodeIds)
          ? step.dependsOnNodeIds.map(String).slice(0, 128)
          : undefined,
        toolCode:
          step.toolCode || step.tool_code || step.tool || `step-${index + 1}`,
        title:
          step.title ||
          step.name ||
          step.label ||
          step.toolCode ||
          step.tool ||
          `步骤 ${index + 1}`,
        reason: boundedString(
          step.reason || step.description || step.summary,
          800,
        ) || "",
        parameters: step.parameters && typeof step.parameters === "object" && !Array.isArray(step.parameters) ? step.parameters : {},
        risk: boundedString(step.risk, 32),
        requiresApproval: step.requiresApproval ?? step.requires_approval,
        status: step.status || "pending",
        taskId: boundedNumber(step.taskId || step.task_id),
      }))
    : undefined;
  // Keep a plan object even when only actions[] was provided by the runtime.
  const normalizedPlan = planRaw
    ? {
        provider: boundedString(planRaw.provider || raw.source, 120) || "",
        model: boundedString(planRaw.model || raw.model, 160) || "",
        summary: boundedString(
          planRaw.summary || raw.summary || raw.message,
          1200,
        ) || "",
        requiresConfirmation: Boolean(
          planRaw.requiresConfirmation ||
            planRaw.requires_confirmation ||
            steps?.some((step) => step.requiresApproval),
        ),
        steps: steps || [],
      }
    : steps
      ? {
          provider: raw.source || raw.provider || "",
          model: raw.model || "",
          summary: raw.summary || raw.message || "",
          requiresConfirmation: steps.some((s: any) => s.requiresApproval),
          steps,
        }
      : undefined;
  const taskIds = Array.isArray(raw.taskIds || responseRaw?.taskIds)
    ? (raw.taskIds || responseRaw?.taskIds)
        .map(Number)
        .filter((id: number) => Number.isFinite(id) && id > 0)
    : undefined;
  const evidenceIds = Array.isArray(raw.evidenceIds)
    ? raw.evidenceIds.filter((id: unknown) => typeof id === "string")
    : [];
  const actions = Array.isArray(raw.actions || planRaw?.actions)
    ? raw.actions || planRaw?.actions
    : [];
  return {
    id: boundedString(raw.id || raw.eventId, 128),
    ...publicProgressProvenance(raw),
    type,
    stage:
      raw.progressStage ||
      raw.stage ||
      raw.phase ||
      raw.node ||
      raw.graphNode ||
      ([
        "planner",
        "executor",
        "reviewer",
        "authorization_guard",
        "approval_required",
        "engagement",
        "engage",
        "reconnaissance",
        "recon",
        "mapping",
        "map",
        "discovery",
        "vulnerability_discovery",
        "validation",
        "validate",
        "impact",
        "impact_assessment",
        "retest",
        "remediation",
        "report",
        "reporting",
      ].includes(originalType)
        ? originalType
        : raw.name),
    status: raw.status || step.status,
    recorded: raw.recorded === true,
    eventTiming: boundedString(raw.eventTiming, 64),
    summary: raw.summary || raw.message || raw.description || step.reason,
    message: raw.message || raw.summary,
    stepId: raw.stepId || step.id || step.step_id,
    stepIndex: raw.stepIndex ?? step.index,
    toolCode: raw.toolCode || step.toolCode || step.tool_code || raw.tool,
    toolName: raw.toolName || raw.tool_name || raw.name,
    toolCallId: raw.toolCallId || raw.tool_call_id || raw.callId,
    taskId: raw.taskId || raw.task_id,
    attempt: raw.attempt ?? raw.retryCount,
    maxAttempts: raw.maxAttempts ?? raw.max_retries,
    approvalId: raw.approvalId || raw.approval_id || responseRaw?.approvalId,
    approvalStatus: raw.approvalStatus || raw.approval_status || responseRaw?.approvalStatus,
    judge:
      raw.judge && typeof raw.judge === "object"
        ? (raw.judge as JudgeVerdictDocument)
        : responseRaw?.judge && typeof responseRaw.judge === "object"
          ? (responseRaw.judge as JudgeVerdictDocument)
          : undefined,
    executionDecision: normalizeAiExecutionDecision(raw.executionDecision),
    modelUsage,
    citation,
    plan: normalizedPlan,
    steps,
    taskCount: boundedNumber(raw.taskCount ?? responseRaw?.taskCount),
    taskIds,
    targetId: raw.targetId || responseRaw?.targetId,
    // 终端 done 帧里 raw.answer 常为空；真正的模型正文在 data.response.message。
    // 这里必须让 responseRaw.message 优先：raw.answer 若被后端填成进度/阶段文案
    // （非空但不是回答），用 `||` 会让进度串顶掉真正的模型回答。
    answer: responseRaw?.message || raw.answer,
    runId: raw.runId || raw.sessionId || responseRaw?.sessionId,
    contractVersion: boundedNumber(raw.contractVersion),
    workflowId: boundedString(raw.workflowId || responseRaw?.workflowId, 64),
    workflowRevision: boundedNumber(
      raw.workflowRevision ?? raw.revision ?? responseRaw?.workflowRevision,
    ),
    workflowDigest: boundedString(
      raw.workflowDigest || raw.specDigest || responseRaw?.workflowDigest,
      71,
    ),
    workflowNodeId: boundedString(
      raw.workflowNodeId ||
        raw.workflow_node_id ||
        raw.nodeId ||
        responseRaw?.workflowNodeId,
      64,
    ),
    outerNodeId: boundedString(
      raw.outerNodeId || responseRaw?.outerNodeId,
      80,
    ),
    nodeRunId: boundedString(raw.nodeRunId || responseRaw?.nodeRunId, 80),
    publicNodeStatus: publicNodeStatus(raw, type),
    innerStep: boundedString(raw.innerStep, 64),
    ledgerSequence: boundedNumber(raw.ledgerSequence),
    ledgerEntryDigest: boundedString(raw.ledgerEntryDigest, 71),
    ledgerDigest: boundedString(
      raw.ledgerDigest || responseRaw?.ledgerDigest,
      71,
    ),
    terminationReason: boundedString(
      raw.terminationReason || responseRaw?.terminationReason,
      80,
    ),
    evidenceCount:
      boundedNumber(raw.evidenceCount) ??
      (evidenceIds.length ? evidenceIds.length : undefined),
    actionCount:
      boundedNumber(raw.actionCount) ??
      (actions.length ? actions.length : undefined),
    recoverable:
      typeof raw.recoverable === "boolean"
        ? raw.recoverable
        : typeof raw.resumeAllowed === "boolean"
          ? raw.resumeAllowed
          : undefined,
    dispatch:
      raw.dispatch && typeof raw.dispatch === "object"
        ? (raw.dispatch as AiDispatch)
        : undefined,
    citations: Array.isArray(raw.citations || responseRaw?.citations)
      ? (raw.citations || responseRaw?.citations).map((item: unknown) => {
          const candidate = eventPayload(item);
          const text = String(
            candidate.snippet || candidate.summary || candidate.text || "",
          );
          return {
            id: boundedString(candidate.id || candidate.citationId, 128),
            title: boundedString(candidate.title || candidate.name, 200),
            source: boundedString(candidate.source || candidate.sourceName, 120),
            url: boundedString(candidate.url || candidate.href, 1000),
            locator: boundedString(candidate.locator || candidate.path, 300),
            summaryLength:
              boundedNumber(candidate.summaryLength) ?? text.length,
          } satisfies ConversationCitation;
        })
      : citation
        ? [citation]
        : undefined,
  };
}

function dispatchFromEvent(
  event: AiDispatchStreamEvent,
): AiDispatch | undefined {
  const normalized = normalizeAgentEvent(event) || (event as AgentStreamEvent);
  // Intermediate plans and replayed ledger entries are useful for display, but
  // only this turn's terminal receipt can complete the active request.
  if (normalized.type !== "done" || normalized.recorded ||
      normalized.eventTiming === "VERIFIED_RECORD" || normalized.status === "RECORDED")
    return undefined;
  const candidate = (normalized.dispatch ||
    normalized) as Partial<AiDispatch>;
  const plan =
    candidate.plan || (normalized.plan as AiDispatch["plan"] | undefined);
  const ids = Array.isArray(candidate.taskIds) ? candidate.taskIds : [];
  // A terminal receipt may contain only an answer/citations and no scan tasks.
  return {
    targetId: Number(candidate.targetId ?? normalized.targetId ?? 0),
    plan: (plan || {
      provider:
        (candidate as any).provider ||
        normalized.provider ||
        (normalized as any).data?.provider ||
        "openai-compatible",
      model: "",
      summary: "",
      requiresConfirmation: false,
      steps: [],
    }) as AiDispatch["plan"],
    taskCount: Number(candidate.taskCount ?? ids.length),
    taskIds: ids.map(Number),
    answer: (candidate.answer || normalized.answer) as string | undefined,
    approvalId: candidate.approvalId || normalized.approvalId,
    approvalStatus: candidate.approvalStatus || normalized.approvalStatus,
    citations: (candidate.citations || normalized.citations) as
      | ConversationCitation[]
      | undefined,
    runId: (candidate.runId || normalized.runId) as string | undefined,
    workflowId: normalized.workflowId,
    workflowRevision: normalized.workflowRevision,
    workflowDigest: normalized.workflowDigest,
    outerNodeId: normalized.outerNodeId,
    nodeRunId: normalized.nodeRunId,
    ledgerDigest: normalized.ledgerDigest,
    terminationReason: normalized.terminationReason,
  };
}

function dispatchFromAgentResponse(
  response: AiAgentResponsePayload,
): AiDispatch {
  const taskIds = Array.isArray(response.taskIds)
    ? response.taskIds.map(Number)
    : [];
  return {
    targetId: Number(response.targetId),
    plan: response.plan || {
      provider: "",
      model: "",
      summary: response.message || "",
      requiresConfirmation: false,
      steps: [],
    },
    taskCount: taskIds.length,
    taskIds,
    answer: response.message,
    approvalId: response.approvalId,
    approvalStatus: response.approvalStatus,
    runId: response.sessionId,
    workflowId: response.workflowId,
    workflowRevision: response.workflowRevision,
    workflowDigest: response.workflowDigest,
    outerNodeId: response.outerNodeId,
    nodeRunId: response.nodeRunId,
    ledgerDigest: response.ledgerDigest,
    terminationReason: response.terminationReason,
  };
}

/**
 * Streams safe, server-authored planning summaries. Hidden model reasoning fields are
 * intentionally ignored by callers; only stage/summary/message should be rendered.
 */
export async function dispatchAiStreaming(
  payload: AiAgentRequestPayload,
  onEvent: (event: AiDispatchStreamEvent) => void,
): Promise<AiDispatch> {
  taskbarProgress.startIndeterminate("ai-agent-stream");
  const controller = new AbortController();
  let idleTimer: ReturnType<typeof setTimeout> | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  // 注意：这里刻意**不**在 fetch 之前启动空闲计时器。
  // STREAM_IDLE_TIMEOUT_MS 的语义是"两次数据之间的最大间隔"，若在建立连接前
  // 就启动，它会把连接握手、鉴权、以及模型首 token 的思考时间一并算进预算；
  // 一次首 token 超过 90 秒的正常慢回答会被整体中止，并被报成传输失败
  // （已流出的部分回答也随之被覆盖）。计时器改为在响应头到达后启动。
  const markStreamActivity = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(
      () => controller.abort("AI stream idle timeout"),
      STREAM_IDLE_TIMEOUT_MS,
    );
  };

  try {
    const token = readAuthToken();
    const agentMode = Number(payload.projectId) > 0;
    if (!agentMode) assertAiLegacyFallbackAllowed(payload);
    const response = await apiFetch(
      apiUrl(agentMode ? "/ai/agent/stream" : "/ai/dispatches/stream"),
      {
        method: "POST",
        headers: {
          Accept: "text/event-stream, application/x-ndjson, application/json",
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      },
    );

    if ([404, 405, 406, 415, 501].includes(response.status) || (response.ok && !response.body)) {
      if (idleTimer) clearTimeout(idleTimer);
      if (agentMode) {
        try {
          return dispatchFromAgentResponse(
            (await endpoints.runAgent(payload)).data,
          );
        } catch (error: any) {
          if (![404, 405, 501].includes(Number(error?.response?.status)))
            throw error;
        }
      }
      assertAiLegacyFallbackAllowed(payload);
      return (
        await endpoints.dispatchAi({
          projectId: payload.projectId,
          targetId: payload.targetId,
          sessionId: payload.sessionId,
          turnId: payload.turnId,
          workflowId: payload.workflowId,
          workflowRevision: payload.workflowRevision,
          workflowDigest: payload.workflowDigest,
          outerNodeId: payload.outerNodeId,
          nodeRunId: payload.nodeRunId,
          prompt: payload.prompt,
          execute: payload.execute,
          executionIntent: payload.executionIntent,
          userPrompt: payload.userPrompt,
          mode: payload.mode,
          refs: payload.refs,
        })
      ).data;
    }
    if (!response.ok) {
      const body = await response.text();
      let message = body || `请求失败：HTTP ${response.status}`;
      try {
        message = JSON.parse(body)?.message || message;
      } catch {
        /* Plain-text error. */
      }
      throw new Error(message);
    }

    const contentType =
      response.headers.get("content-type")?.toLowerCase() || "";
    if (contentType.includes("application/json")) {
      markStreamActivity();
      const json = await response.json();
      return agentMode
        ? dispatchFromAgentResponse(json as AiAgentResponsePayload)
        : (json as AiDispatch);
    }

    if (!response.body) throw new Error("AI 流式响应缺少响应体");
    // 响应头已到达：从这一刻起才启动"两次数据之间的最大间隔"计时。
    markStreamActivity();
    reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let sseData: string[] = [];
    let sseType = "";
    let completed: AiDispatch | undefined;

    const emitText = (raw: string) => {
      if (completed) return;
      const text = raw.trim();
      if (!text || text === "[DONE]") return;
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        // Some providers send a plain text status line. Preserve it as a
        // bounded progress event instead of terminating the whole run.
        parsed = { type: sseType || "progress", message: text.slice(0, 800) };
      }
      const event = normalizeAgentEvent(parsed, sseType) as
        | AiDispatchStreamEvent
        | undefined;
      if (!event) return;
      markStreamActivity();
      onEvent(event);
      completed = dispatchFromEvent(event) || completed;
      if (event.type === "error")
        throw new Error(event.message || "AI 无法派发任务");
    };
    const processLine = (line: string) => {
      if (contentType.includes("text/event-stream")) {
        if (!line.trim()) {
          if (sseData.length) emitText(sseData.join("\n"));
          sseData = [];
          sseType = "";
        } else if (line.startsWith("data:")) {
          sseData.push(line.slice(5).trimStart());
        } else if (line.startsWith("event:")) {
          sseType = line.slice(6).trim();
        }
      } else if (line.trim()) {
        emitText(line);
      }
    };

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      // Receiving bytes (including a split frame or SSE keepalive) proves the
      // transport is active; it does not manufacture a visible progress event.
      if (value.byteLength) markStreamActivity();
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || "";
      lines.forEach(processLine);
      if (completed) return completed;
    }
    buffer += decoder.decode();
    if (buffer) processLine(buffer);
    if (sseData.length) emitText(sseData.join("\n"));
    if (!completed)
      throw new Error("AI 流式响应已结束，但没有返回任务派发结果");
    return completed;
  } catch (error) {
    if (controller.signal.aborted) {
      const timeoutError = new Error(
        "AI 长时间没有返回新的进度，请稍后再试。",
      ) as Error & { code?: string };
      timeoutError.code = "ECONNABORTED";
      throw timeoutError;
    }
    throw error;
  } finally {
    taskbarProgress.stopIndeterminate("ai-agent-stream");
    if (idleTimer) clearTimeout(idleTimer);
    if (reader) {
      // A terminal receipt/error need not be followed by a timely socket EOF.
      // Release the transport without waiting for the remote close handshake.
      void reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }
}

export interface TargetedScanProbe {
  name: string;
  method: string;
  target: string;
  payload?: string;
  statusCode?: number | null;
  responseSnippet?: string;
  triggered: boolean;
  note?: string;
}

export interface TargetedScanHit {
  title: string;
  severity: string;
  description: string;
  parameter?: string;
  evidence?: string;
  solution?: string;
}

export interface TargetedScanResult {
  scanId?: number;
  packetId: number;
  engine: string;
  status: string;
  hits: TargetedScanHit[];
  probes?: TargetedScanProbe[];
  message: string;
}

export type ZapScanStreamEvent =
  | { type: "start"; targetUrl?: string }
  | { type: "record"; scanId: number }
  | { type: "status"; message?: string }
  | { type: "probe"; probe: TargetedScanProbe }
  | { type: "hit"; hit: TargetedScanHit }
  | { type: "complete"; result: TargetedScanResult }
  | { type: "error"; message?: string };

/**
 * 以 SSE 流式方式执行定向扫描：每产出一条结果立即回调，
 * 便于前端实时展示测试数据，而不是等整轮结束才出结果。
 */
async function streamTargetedScan(
  path: string,
  payload: Record<string, unknown>,
  onEvent: (event: ZapScanStreamEvent) => void,
): Promise<TargetedScanResult> {
  const token = readAuthToken();
  const response = await apiFetch(apiUrl(path), {
    method: "POST",
    headers: {
      Accept: "text/event-stream, application/json",
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok || !response.body) {
    const text = await response.text().catch(() => "");
    let message = text || `请求失败：HTTP ${response.status}`;
    try {
      message = JSON.parse(text)?.message || message;
    } catch {
      /* 纯文本错误 */
    }
    throw new Error(message);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result: TargetedScanResult | undefined;

  const handleLine = (line: string) => {
    if (!line.startsWith("data:")) return;
    const text = line.slice(5).trim();
    if (!text) return;
    let event: ZapScanStreamEvent;
    try {
      event = JSON.parse(text) as ZapScanStreamEvent;
    } catch {
      return;
    }
    onEvent(event);
    if (event.type === "complete") {
      if (!event.result || typeof event.result !== "object") {
        throw new Error("检测连接已结束，但没有收到有效的检测结果");
      }
      result = event.result;
    }
    if (event.type === "error") throw new Error(event.message || "定向扫描失败");
  };

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || "";
      for (const line of lines) {
        handleLine(line);
        // A confirmed terminal result does not require the server to close its socket.
        if (result) return result;
      }
    }
    buffer += decoder.decode();
    if (buffer.trim()) handleLine(buffer);
    if (!result) throw new Error("流式响应已结束，但没有返回扫描结果");
    return result;
  } finally {
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export function streamZapScan(
  packetId: number | string,
  payload: { targetId?: number; strength?: string; policy?: string },
  onEvent: (event: ZapScanStreamEvent) => void,
): Promise<TargetedScanResult> {
  return streamTargetedScan(
    `/traffic/packets/${packetId}/zap-scan/stream`,
    payload,
    onEvent,
  );
}

export function streamXrayScan(
  packetId: number | string,
  payload: { targetId?: number; allPocs?: boolean; pocCodes?: string[] },
  onEvent: (event: ZapScanStreamEvent) => void,
): Promise<TargetedScanResult> {
  return streamTargetedScan(
    `/traffic/packets/${packetId}/xray-scan/stream`,
    payload,
    onEvent,
  );
}

export function streamSqlmapScan(
  packetId: number | string,
  payload: { targetId?: number; level?: number; risk?: number; technique?: string; data?: string },
  onEvent: (event: ZapScanStreamEvent) => void,
): Promise<TargetedScanResult> {
  return streamTargetedScan(
    `/traffic/packets/${packetId}/sqlmap-scan/stream`,
    payload,
    onEvent,
  );
}

export async function safeGet<T>(
  request: () => Promise<{ data: T }>,
  fallback: T,
) {
  try {
    return { data: (await request()).data, offline: false };
  } catch {
    return { data: fallback, offline: true };
  }
}
