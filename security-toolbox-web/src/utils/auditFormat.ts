/**
 * 审计日志中文化与格式化映射工具
 */

export const AUDIT_ACTION_LABELS: Record<string, string> = {
  // 身份与认证
  LOGIN: "用户登录",
  LOGOUT: "用户登出",

  // 项目管理
  CREATE_PROJECT: "创建评估项目",
  UPDATE_PROJECT: "修改评估项目",
  UPDATE_PROJECT_STATUS: "更新项目状态",
  DELETE_PROJECT: "删除评估项目",
  ADD_PROJECT_TARGET: "添加授权目标",
  REMOVE_PROJECT_TARGET: "移除授权目标",

  // 目标管理
  CREATE_TARGET: "新建授权目标",
  UPDATE_TARGET: "修改授权目标",
  DELETE_TARGET: "删除授权目标",

  // 任务与工具执行
  CREATE_TASK: "创建检测任务",
  EXECUTE_TOOL: "执行安全工具",
  CANCEL_TASK: "取消检测任务",
  RETRY_TASK: "重试检测任务",

  // 工作流
  CREATE_WORKFLOW_TASK: "创建工作流任务",
  UNLOCK_WORKFLOW_TASK: "解锁后继任务",
  SKIP_WORKFLOW_TASK: "跳过工作流任务",
  CANCEL_WORKFLOW_TASK: "取消工作流任务",
  START_WORKFLOW_RUN: "启动工作流",
  STOP_WORKFLOW_RUN: "停止工作流",
  CLEAR_WORKFLOW_RUN: "清理工作流历史",

  // 漏洞与发现
  UPDATE_FINDING_STATUS: "更新漏洞状态",
  DELETE_FINDING: "删除漏洞记录",
  CLEAR_FINDINGS: "清空漏洞结果",
  RETEST_FINDING: "漏洞复测",
  CREATE_POST_SCAN_PATH: "生成验证路径",
  CONFIRM_POST_SCAN_PATH: "确认执行验证路径",
  COMPARE_SCAN_DIFF: "扫描比对",

  // 知识库与特征库
  SYNC_VULNERABILITY_CATALOG: "同步漏洞特征库",
  CLEAR_VULNERABILITY_CATALOG: "清空漏洞特征库",
  UPDATE_FINGERPRINT_CATALOG: "更新指纹规则库",

  // 流量捕获与分析
  START_TRAFFIC_PROXY: "启动流量代理",
  STOP_TRAFFIC_PROXY: "停止流量代理",
  START_TRAFFIC_CAPTURE: "开启流量拦截",
  STOP_TRAFFIC_CAPTURE: "停止流量拦截",
  ANALYZE_TRAFFIC: "AI 流量分析",
  EXECUTE_TRAFFIC_ACTION: "执行流量处置",
  REJECT_TRAFFIC_ACTION: "忽略流量处置",
  REPLAY_TRAFFIC_PACKET: "流量重放发包",
  MARK_TRAFFIC_PACKET: "标记重点流量",
  UNMARK_TRAFFIC_PACKET: "取消流量标记",
  DELETE_TRAFFIC_PACKET: "删除流量记录",
  CLEAR_TRAFFIC_PACKETS: "清理未标记流量",
  AI_CHAT_TRAFFIC: "流量 AI 对话",
  CREATE_TRAFFIC_CAPTURE_FILTER: "新增抓包过滤",
  UPDATE_TRAFFIC_CAPTURE_FILTER: "更新抓包过滤",
  DELETE_TRAFFIC_CAPTURE_FILTER: "删除抓包过滤",
  TRAFFIC_XRAY_SCAN: "流量联动 Xray 扫描",
  TRAFFIC_ZAP_SCAN: "流量联动 ZAP 扫描",

  // 安全管控与审批
  REQUEST_SECURITY_ACTION: "申请受控动作",
  DECIDE_SECURITY_ACTION: "审批受控动作",
  START_SECURITY_ACTION: "执行受控动作",
  COMPLETE_SECURITY_ACTION: "完成受控动作",
  ROLLBACK_SECURITY_ACTION: "回滚受控动作",
  PROJECT_APPROVAL_REQUEST: "发起高危审批",
  PROJECT_APPROVAL_DECIDE: "审批高危任务",

  // AI 智能问答与调度
  AI_CREATE_PLAN: "AI 生成检测计划",
  AI_ANSWER_TASK_RESULTS: "AI 汇总任务结论",
  AI_DISPATCH_TASKS: "AI 调度下发任务",
  AI_AGENT_TURN: "AI 对话交互",
  AI_CONVERSATION_DELETE: "删除 AI 对话",
  AGENT_CONTINUATION_CHECKPOINT: "AI 恢复检查点",
  AGENT_CONTINUATION_COMPLETED: "AI 续接任务完成",
  AGENT_CONTINUATION_SKIPPED: "跳过 AI 续接",
  AGENT_CONTINUATION_REJECTED: "拒绝 AI 续接",

  // 任务重测与跳过
  RETEST_TASK: "漏洞复测任务",
  SKIP_UNAVAILABLE_WORKFLOW_TASK: "跳过不可用工作流任务",

  // 系统运维
  CLEAR_BUSINESS_DATA: "清空业务数据",
};

export const AUDIT_RESOURCE_LABELS: Record<string, string> = {
  USER: "用户账户",
  PROJECT: "评估项目",
  TARGET: "授权目标",
  TASK: "检测任务",
  FINDING: "风险漏洞",
  VULNERABILITY: "漏洞特征库",
  FINGERPRINT_CATALOG: "指纹规则库",
  TRAFFIC_PACKET: "流量报文",
  TRAFFIC_SESSION: "流量代理会话",
  TRAFFIC_SUGGESTION: "流量处置建议",
  TRAFFIC_CAPTURE_FILTER: "抓包过滤规则",
  AI_CONVERSATION: "AI 对话会话",
  SYSTEM_DATA: "系统数据",
};

export const AUDIT_RESULT_META: Record<
  string,
  { label: string; tagType: "success" | "danger" | "warning" | "info" | "primary" }
> = {
  SUCCESS: { label: "成功", tagType: "success" },
  COMPLETED: { label: "完成", tagType: "success" },
  CONTINUED: { label: "自动续接", tagType: "success" },
  ACCEPTED: { label: "已受理", tagType: "primary" },
  FAILED: { label: "失败", tagType: "danger" },
  BLOCKED: { label: "已拦截", tagType: "danger" },
  REJECTED: { label: "已拒绝", tagType: "warning" },
  TIMEOUT: { label: "超时", tagType: "warning" },
  NOT_FOUND: { label: "未找到", tagType: "warning" },
  STALE: { label: "已失效", tagType: "warning" },
  CANCELLED: { label: "已取消", tagType: "info" },
  SKIPPED: { label: "已跳过", tagType: "info" },
  WAITING_TASKS: { label: "等待前置", tagType: "info" },
};

export const APPROVAL_ACTION_LABELS: Record<string, string> = {
  SCAN: "主动扫描",
  RETEST: "漏洞复测",
  POST_SCAN: "后续验证",
  OTHER: "其他安全操作",
};

export const PROJECT_STATUS_LABELS: Record<string, string> = {
  ACTIVE: "进行中",
  DRAFT: "草稿",
  PAUSED: "已暂停",
  COMPLETED: "已完成",
  ARCHIVED: "已归档",
};

export const APPROVAL_STATUS_LABELS: Record<string, string> = {
  PENDING: "待审批",
  APPROVED: "已通过",
  REJECTED: "已拒绝",
};

export const FINDING_STATUS_LABELS: Record<string, string> = {
  OPEN: "待确认",
  CONFIRMED: "已确认",
  FALSE_POSITIVE: "误报",
  FIXED: "已修复",
};

export const TASK_STATUS_LABELS: Record<string, string> = {
  PENDING: "待执行",
  QUEUED: "排队中",
  BLOCKED: "等待前置",
  RUNNING: "执行中",
  SUCCESS: "成功",
  FAILED: "失败",
  TIMEOUT: "超时",
  CANCELLED: "已取消",
  REJECTED: "已拒绝",
  SKIPPED: "已跳过",
};

export function formatApprovalAction(action?: string): string {
  if (!action) return "未知动作";
  const key = String(action).trim().toUpperCase();
  return APPROVAL_ACTION_LABELS[key] || action;
}

export function formatAuditOperator(operator?: string): string {
  if (!operator) return "系统";
  const op = String(operator).trim();
  if (op === "anonymousUser" || op === "anonymous") return "未认证用户";
  if (op === "system" || op === "SYSTEM") return "系统进程";
  return op;
}

export function formatAuditDetail(detail?: string): string {
  if (!detail) return "-";
  let text = String(detail).trim();
  if (!text) return "-";

  // 结构化前缀处理
  text = text.replace(/approvalId\s*=\s*(\d+)/gi, "审批单#$1");
  text = text.replace(/projectId\s*=\s*(\d+)/gi, "项目#$1");
  text = text.replace(/taskId\s*=\s*(\d+)/gi, "任务#$1");
  text = text.replace(/actionId\s*=\s*(\d+)/gi, "动作#$1");
  text = text.replace(/targetId\s*=\s*(\d+)/gi, "目标#$1");
  text = text.replace(/runId\s*=\s*(\d+)/gi, "运行#$1");
  text = text.replace(/baselineTaskId\s*=\s*(\d+)/gi, "基线任务#$1");
  text = text.replace(/retestTaskId\s*=\s*(\d+)/gi, "复测任务#$1");
  text = text.replace(/pathId\s*=\s*(\d+)/gi, "路径#$1");
  text = text.replace(/sessionId\s*=\s*(\d+)/gi, "会话#$1");
  text = text.replace(/sourceTaskId\s*=\s*(\d+)/gi, "源任务#$1");
  text = text.replace(/workflowNodeId\s*=\s*([a-zA-Z0-9_-]+)/gi, "工作流节点#$1");

  // 指标统计与字段键名
  text = text.replace(/\bhits\s*=\s*(\d+)/gi, "检出漏洞=$1");
  text = text.replace(/\bdeletedCount\s*=\s*(\d+)/gi, "已删除=$1");
  text = text.replace(/\bretainedCount\s*=\s*(\d+)/gi, "已保留=$1");
  text = text.replace(/\bdiscovered\s*=\s*(\d+)/gi, "已发现=$1");
  text = text.replace(/\bimported\s*=\s*(\d+)/gi, "已导入=$1");
  text = text.replace(/\bupdated\s*=\s*(\d+)/gi, "已更新=$1");
  text = text.replace(/\bremoved\s*=\s*(\d+)/gi, "已移除=$1");
  text = text.replace(/\bdeletedPaths\s*=\s*(\d+)/gi, "已删除路径=$1");
  text = text.replace(/\bmissingPaths\s*=\s*(\d+)/gi, "缺失路径=$1");
  text = text.replace(/\bautomatedSteps\s*=\s*(\d+)/gi, "自动化步骤=$1");

  text = text.replace(/\btaskIds\s*=/gi, "关联任务=");
  text = text.replace(/\bfindingIds\s*=/gi, "关联漏洞=");
  text = text.replace(/\bprovider\s*=\s*local-rule-fallback/gi, "服务源=本地规则兜底");
  text = text.replace(/\bprovider\s*=\s*local-rule/gi, "服务源=本地规则引擎");
  text = text.replace(/\bprovider\s*=\s*local-model/gi, "服务源=本地大模型");
  text = text.replace(/\bprovider\s*=\s*remote-api/gi, "服务源=远程接口");
  text = text.replace(/\bprovider\s*=/gi, "服务源=");
  text = text.replace(/\bprompt\s*=/gi, "提示词=");
  text = text.replace(/\berror\s*=/gi, "错误=");
  text = text.replace(/\breason\s*=/gi, "原因=");
  text = text.replace(/\bport\s*=/gi, "端口=");
  text = text.replace(/\bsource\s*=\s*nuclei/gi, "数据源=Nuclei");
  text = text.replace(/\bsource\s*=\s*afrog/gi, "数据源=Afrog");
  text = text.replace(/\bsource\s*=\s*xray/gi, "数据源=Xray");
  text = text.replace(/\bsource\s*=\s*msf/gi, "数据源=Metasploit");
  text = text.replace(/\bsource\s*=/gi, "数据源=");
  text = text.replace(/\bmode\s*=/gi, "模式=");

  text = text.replace(/\bcapturing\s*=\s*true/gi, "拦截开启");
  text = text.replace(/\bcapturing\s*=\s*false/gi, "拦截停止");
  text = text.replace(/\bmarked\s*=\s*true/gi, "重点标记=是");
  text = text.replace(/\bmarked\s*=\s*false/gi, "重点标记=否");
  text = text.replace(/\benabled\s*=\s*true/gi, "启用=是");
  text = text.replace(/\benabled\s*=\s*false/gi, "启用=否");
  text = text.replace(/\bcleared\s*=\s*true/gi, "已清空");
  text = text.replace(/\bcleared\s*=\s*false/gi, "未清空");

  // 工具名称中文化
  text = text.replace(/\btcp_ports\b/g, "TCP 端口探测");
  text = text.replace(/\bnmap_service_scan\b/g, "Nmap 服务识别");
  text = text.replace(/\bhttp_headers\b/g, "HTTP 响应头检查");
  text = text.replace(/\bhttp_security_check\b/g, "HTTP 常见安全检查");
  text = text.replace(/\btls_config\b/g, "TLS 配置检查");
  text = text.replace(/\bnuclei_scan\b/g, "Nuclei 漏洞扫描");
  text = text.replace(/\bafrog_scan\b/g, "Afrog 漏洞扫描");
  text = text.replace(/\bxray_scan\b/g, "Xray 漏洞扫描");
  text = text.replace(/\bzap_scan\b/g, "OWASP ZAP 扫描");
  text = text.replace(/\bfscan_scan\b/g, "fscan 主机扫描");
  text = text.replace(/\bmsf_scan\b/g, "Metasploit 模块扫描");

  // 统一中文化所有已知英文枚举（大小写不敏感，使用单词边界）
  const tokenMap: Record<string, string> = {
    ...PROJECT_STATUS_LABELS,
    ...APPROVAL_STATUS_LABELS,
    ...APPROVAL_ACTION_LABELS,
    ...FINDING_STATUS_LABELS,
    ...TASK_STATUS_LABELS,
    NONE: "无",
    STOPPED: "已停止",
    IGNORED: "已忽略",
  };
  Object.entries(tokenMap).forEach(([en, zh]) => {
    text = text.replace(new RegExp(`\\b${en}\\b`, "gi"), zh);
  });

  // key=value 形式残留的英文 key 也中文化
  text = text
    .replace(/\bstatus\s*=/gi, "状态=")
    .replace(/\baction\s*=/gi, "动作=")
    .replace(/\bdecision\s*=/gi, "决定=");

  return text;
}

export function formatAuditAction(action?: string): string {
  if (!action) return "未知操作";
  const key = String(action).trim().toUpperCase();
  return AUDIT_ACTION_LABELS[key] || action;
}

export function formatAuditResource(resource?: string): string {
  if (!resource) return "未指定";
  const key = String(resource).trim().toUpperCase();
  return AUDIT_RESOURCE_LABELS[key] || resource;
}

export function formatAuditResult(result?: string): string {
  if (!result) return "未知";
  const key = String(result).trim().toUpperCase();
  return AUDIT_RESULT_META[key]?.label || result;
}

export function auditResultTagType(
  result?: string,
): "success" | "danger" | "warning" | "info" | "primary" {
  if (!result) return "info";
  const key = String(result).trim().toUpperCase();
  return AUDIT_RESULT_META[key]?.tagType || "info";
}
