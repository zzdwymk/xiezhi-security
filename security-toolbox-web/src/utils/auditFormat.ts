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
  BATCH_CREATE_TASK: "批量创建任务",
  EXECUTE_TOOL: "执行安全工具",
  CANCEL_TASK: "取消检测任务",
  RETRY_TASK: "重试检测任务",

  // 工作流
  CREATE_WORKFLOW_TASK: "创建工作流任务",
  UNLOCK_WORKFLOW_TASK: "解锁后继任务",
  REQUEUE_WORKFLOW_TASK: "重新排队工作流任务",
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
  RETEST_VERDICT: "记录复测结论",
  CREATE_POST_SCAN_PATH: "生成验证路径",
  CONFIRM_POST_SCAN_PATH: "确认执行验证路径",
  COMPARE_SCAN_DIFF: "扫描比对",

  // 知识库与特征库
  SYNC_VULNERABILITY_CATALOG: "同步漏洞特征库",
  CLEAR_VULNERABILITY_CATALOG: "清空漏洞特征库",
  UPDATE_FINGERPRINT_CATALOG: "更新指纹规则库",
  ADD_FINGERPRINT_RULE: "新增指纹规则",
  UPDATE_FINGERPRINT_RULE: "更新指纹规则",
  DELETE_FINGERPRINT_RULE: "删除指纹规则",

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
  TRAFFIC_SQLMAP_SCAN: "流量联动 SQL 注入检测",

  // 安全管控与审批
  REQUEST_SECURITY_ACTION: "申请受控动作",
  DECIDE_SECURITY_ACTION: "审批受控动作",
  START_SECURITY_ACTION: "执行受控动作",
  COMPLETE_SECURITY_ACTION: "完成受控动作",
  ROLLBACK_SECURITY_ACTION: "回滚受控动作",
  PROJECT_APPROVAL_REQUEST: "AI 提交行动方案",
  PROJECT_APPROVAL_DECIDE: "管理员确认行动方案",
  AGENT_CAPABILITY_APPROVAL_REQUESTED: "申请受控能力审批",
  AGENT_CAPABILITY_DENIED: "受控能力拦截",

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
  FINGERPRINT_RULE: "指纹规则",
  TRAFFIC_PACKET: "流量报文",
  TRAFFIC_SESSION: "流量代理会话",
  TRAFFIC_SUGGESTION: "流量处置建议",
  TRAFFIC_CAPTURE_FILTER: "抓包过滤规则",
  AI_CONVERSATION: "AI 对话会话",
  SYSTEM_DATA: "系统数据",
  AGENT_CAPABILITY: "受控安全能力",
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
  FAILURE: { label: "失败", tagType: "danger" },
  PENDING: { label: "待处理", tagType: "info" },
  BLOCKED: { label: "已拦截", tagType: "danger" },
  REJECTED: { label: "已拒绝", tagType: "warning" },
  TIMEOUT: { label: "超时", tagType: "warning" },
  NOT_FOUND: { label: "未找到", tagType: "warning" },
  STALE: { label: "已失效", tagType: "warning" },
  CANCELLED: { label: "已取消", tagType: "info" },
  SKIPPED: { label: "已跳过", tagType: "info" },
  WAITING_TASKS: { label: "等待前置", tagType: "info" },
  DENIED: { label: "已拦截", tagType: "danger" },
};

export const APPROVAL_ACTION_LABELS: Record<string, string> = {
  SCAN: "主动扫描",
  RETEST: "漏洞复测",
  POST_SCAN: "后续验证",
  AI_PLAN_EXECUTION: "AI 渗透行动方案",
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
  REOPENED: "已复现",
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

export const AUDIT_TOOL_LABELS: Record<string, string> = {
  tcp_ports: "TCP 端口探测",
  nmap_service_scan: "Nmap 服务识别",
  http_headers: "HTTP 响应头检查",
  http_security_check: "HTTP 常见安全检查",
  tls_config: "TLS 配置检查",
  nuclei_scan: "Nuclei 漏洞扫描",
  afrog_scan: "Afrog 漏洞扫描",
  xray_scan: "Xray 漏洞扫描",
  zap_scan: "OWASP ZAP 扫描",
  sqlmap_scan: "sqlmap SQL 注入检测",
  fscan_scan: "fscan 主机扫描",
  msf_scan: "Metasploit 模块扫描",
};

export function formatApprovalAction(action?: string): string {
  if (!action) return "未知动作";
  const key = String(action).trim().toUpperCase();
  return APPROVAL_ACTION_LABELS[key] || "未知动作";
}

export function formatAuditOperator(operator?: string): string {
  if (!operator) return "系统";
  const op = String(operator).trim();
  if (op === "anonymousUser" || op === "anonymous") return "未认证用户";
  if (op === "system" || op === "SYSTEM") return "系统进程";
  if (op === "ai-agent") return "AI 助手";
  return op;
}

function formatStructuredAuditJson(parsed: Record<string, any>): string | null {
  // 1. 清空业务数据：结构化 JSON 渲染为中文摘要，不暴露数据库 schema。
  if (parsed.deletedByCategory !== undefined || parsed.deletedRecords !== undefined) {
    const parts: string[] = [];
    if (typeof parsed.deletedProjects === "number") {
      parts.push(`评估项目 ${parsed.deletedProjects} 个`);
    }
    if (typeof parsed.deletedRecords === "number") {
      parts.push(`业务记录 ${parsed.deletedRecords} 条`);
    }
    if (typeof parsed.runtimeDocumentsDeleted === "number" && parsed.runtimeDocumentsDeleted > 0) {
      parts.push(`运行时索引文档 ${parsed.runtimeDocumentsDeleted} 条`);
    }
    const cleared = Object.entries((parsed.deletedByCategory as Record<string, number>) || {})
      .filter(([, count]) => count > 0)
      .map(([category, count]) => `${category} ${count} 条`);
    if (cleared.length > 0) {
      parts.push(`其中：${cleared.join("、")}`);
    }
    if (Array.isArray(parsed.preservedData) && parsed.preservedData.length > 0) {
      parts.push(`已保留：${parsed.preservedData.join("、")}`);
    }
    return `已清空全部业务数据（${parts.join("；")}）`;
  }

  // 2. AI 对话交互 / 调度追踪 (AI_AGENT_TURN)
  if (
    parsed.schemaVersion !== undefined ||
    parsed.executionDecision !== undefined ||
    parsed.turnId !== undefined ||
    parsed.ledgerSequence !== undefined ||
    parsed.plannerSource !== undefined
  ) {
    const decisionMap: Record<string, string> = {
      CLARIFY: "需向用户澄清",
      EXECUTE: "执行安全方案",
      PLAN_ONLY: "生成待确认方案",
      STOP: "终止流程",
      TERMINATE: "终止流程",
      MANUAL: "转交人工确认",
    };

    let actionDesc = "";
    if (parsed.error) {
      actionDesc = `AI 交互异常：${parsed.error}`;
    } else if (parsed.executionDecision && decisionMap[parsed.executionDecision]) {
      actionDesc = `AI 决策：${decisionMap[parsed.executionDecision]}`;
    } else if (parsed.executed) {
      actionDesc = "AI 方案已执行";
    } else {
      actionDesc = "AI 交互已完成";
    }

    const parts: string[] = [];
    if (parsed.projectId) {
      parts.push(`项目 #${parsed.projectId}`);
    }
    if (parsed.targetId) {
      parts.push(`目标 #${parsed.targetId}`);
    }
    if (Array.isArray(parsed.taskIds) && parsed.taskIds.length > 0) {
      if (parsed.taskIds.length === 1) {
        parts.push(`派发任务 #${parsed.taskIds[0]}`);
      } else {
        parts.push(
          `派发任务 ${parsed.taskIds.length} 项（${parsed.taskIds.map((id: any) => `#${id}`).join("、")}）`,
        );
      }
    } else if (parsed.executed === false) {
      parts.push("未派发新任务");
    }
    if (parsed.fallback) {
      const fbReason =
        parsed.fallbackReason &&
        parsed.fallbackReason !== "无" &&
        parsed.fallbackReason !== "NONE"
          ? `（${parsed.fallbackReason}）`
          : "";
      parts.push(`规则引擎兜底${fbReason}`);
    }
    if (parsed.ledgerSequence !== undefined && parsed.ledgerSequence !== null) {
      parts.push(`账本序列 #${parsed.ledgerSequence}`);
    }

    return parts.length > 0 ? `${actionDesc}（${parts.join("，")}）` : actionDesc;
  }

  // 3. AI 会话清理 (AI_CONVERSATION_DELETE)
  if (parsed.cleared !== undefined && (parsed.sessionId || parsed.projectId)) {
    const parts: string[] = [];
    if (parsed.projectId) parts.push(`项目 #${parsed.projectId}`);
    if (parsed.targetId) parts.push(`目标 #${parsed.targetId}`);
    if (parsed.sessionId) parts.push(`会话 #${String(parsed.sessionId).slice(0, 8)}`);
    return `已清理 AI 对话记忆（${parts.join("，")}）`;
  }

  // 4. 指纹规则库更新 (UPDATE_FINGERPRINT_CATALOG)
  if (parsed.ruleCount !== undefined) {
    const parts: string[] = [`规则数：${parsed.ruleCount}`];
    if (parsed.version) parts.push(`版本：${parsed.version}`);
    if (parsed.source) parts.push(`来源：${parsed.source === "DEFAULT" ? "内置" : parsed.source}`);
    return `已更新指纹规则库（${parts.join("，")}）`;
  }

  // 5. 护栏受控能力 (AGENT_CAPABILITY / AGENT_CAPABILITY_DENIED)
  if (parsed.capability !== undefined) {
    const capCode = String(parsed.capability);
    const capName = AUDIT_TOOL_LABELS[capCode] || capCode;
    if (parsed.deniedReason) {
      const reasonMap: Record<string, string> = {
        APPROVAL_REQUIRED: "需要人工逐次确认",
        BLOCKED_CAPABILITY: "能力已被禁用",
        TARGET_NOT_AUTHORIZED: "目标未经授权",
        INVALID_PARAMETERS: "参数校验未通过",
      };
      const reason = reasonMap[parsed.deniedReason] || parsed.deniedReason;
      return `受控能力拦截：${capName}（原因：${reason}）`;
    }
    const parts: string[] = [];
    if (parsed.approvalLevel) parts.push(`审批等级：${parsed.approvalLevel}`);
    return `受控能力放行：${capName}${parts.length > 0 ? `（${parts.join("，")}）` : ""}`;
  }

  // 6. 通用 JSON 对象的健壮中文化降级：键名与枚举翻译，彻底杜绝裸露 JSON
  const IGNORED_JSON_KEYS = new Set([
    "schemaVersion",
    "turnId",
    "runtimerRunId",
    "runtimeRunId",
    "workflowDigest",
    "outerNodeId",
    "nodeRunId",
    "ledgerEntryDigest",
    "indexRevision",
    "evidenceIds",
  ]);

  const KEY_LABELS: Record<string, string> = {
    projectId: "项目",
    targetId: "目标",
    taskId: "任务",
    taskIds: "任务列表",
    actionId: "动作",
    sessionId: "会话",
    status: "状态",
    result: "结果",
    reason: "原因",
    error: "错误",
    message: "信息",
    count: "数量",
    total: "总数",
    port: "端口",
    mode: "模式",
    source: "来源",
    version: "版本",
    operator: "操作人",
    approvalId: "审批单",
    ledgerSequence: "账本序列",
    capability: "能力",
    executionDecision: "执行决策",
    executionIntent: "执行意图",
    plannerSource: "规划来源",
  };

  const VALUE_LABELS: Record<string, string> = {
    SUCCESS: "成功",
    FAILED: "失败",
    FAILURE: "失败",
    PENDING: "待处理",
    AUTO: "自动",
    MANUAL: "手动",
    CLARIFY: "需向用户澄清",
    EXECUTE: "执行安全方案",
    PLAN_ONLY: "生成待确认方案",
    NONE: "无",
    true: "是",
    false: "否",
  };

  const entries: string[] = [];
  for (const [key, val] of Object.entries(parsed)) {
    if (IGNORED_JSON_KEYS.has(key) || val === null || val === undefined || val === "") continue;
    const label = KEY_LABELS[key] || key;
    let formattedVal = String(val);
    if (typeof val === "boolean") {
      formattedVal = val ? "是" : "否";
    } else if (Array.isArray(val)) {
      if (val.length === 0) continue;
      formattedVal = val.map((v) => VALUE_LABELS[String(v)] || String(v)).join("、");
    } else if (typeof val === "string" && VALUE_LABELS[val]) {
      formattedVal = VALUE_LABELS[val];
    }
    entries.push(`${label}：${formattedVal}`);
  }

  if (entries.length > 0) {
    return entries.join("；");
  }
  return null;
}

export function formatAuditDetail(detail?: string): string {
  if (!detail) return "-";
  let text = String(detail).trim();
  if (!text) return "-";

  // 尝试解析结构化 JSON
  if (text.startsWith("{") && text.endsWith("}")) {
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const formatted = formatStructuredAuditJson(parsed);
        if (formatted) return formatted;
      }
    } catch {
      // JSON 解析失败则回退到通用文本处理。
    }
  }

  // 常见操作用完整短句展示，同时兼容已有审计记录。
  text = text.replace(
    /^status\s*=\s*([A-Z_]+)\s*[,;]\s*hits\s*=\s*(\d+)$/i,
    "$1，检出 $2 个漏洞",
  );
  text = text.replace(
    /^targetId\s*=\s*(NONE|null)\s*[,;]\s*port\s*=\s*(\d+)$/i,
    "未关联目标，监听端口：$2",
  );
  text = text.replace(
    /^targetId\s*=\s*(\d+)\s*[,;]\s*port\s*=\s*(\d+)$/i,
    "目标 #$1，监听端口：$2",
  );

  // 结构化前缀处理（优先匹配复合键名，添加单词边界避免子串误伤）
  text = text.replace(/\bapprovalId\s*=\s*(\d+)/gi, "审批单#$1");
  text = text.replace(/\bprojectId\s*=\s*(\d+)/gi, "项目#$1");
  text = text.replace(/\bproject\s*=\s*(\d+)/gi, "项目#$1");
  text = text.replace(/\bbaselineTaskId\s*=\s*(\d+)/gi, "基线任务#$1");
  text = text.replace(/\bretestTaskId\s*=\s*(\d+)/gi, "复测任务#$1");
  text = text.replace(/\bsourceTaskId\s*=\s*(\d+)/gi, "源任务#$1");
  text = text.replace(/\btaskId\s*=\s*(\d+)/gi, "任务#$1");
  text = text.replace(/\bactionId\s*=\s*(\d+)/gi, "动作#$1");
  text = text.replace(/\btargetId\s*=\s*(\d+)/gi, "目标#$1");
  text = text.replace(/\brunId\s*=\s*(\d+)/gi, "运行#$1");
  text = text.replace(/\bpathId\s*=\s*(\d+)/gi, "路径#$1");
  text = text.replace(/\bsessionId\s*=\s*([a-zA-Z0-9_-]+)/gi, "会话#$1");
  text = text.replace(/\bworkflowNodeId\s*=\s*([a-zA-Z0-9_-]+)/gi, "工作流节点#$1");
  text = text.replace(/\bledgerSequence\s*=\s*(\d+)/gi, "账本序列#$1");
  text = text.replace(/\bturnId\s*=\s*([a-zA-Z0-9_-]+)/gi, "轮次#$1");
  text = text.replace(/\bexecutionDecision\s*=\s*([a-zA-Z_]+)/gi, "执行决策：$1");
  text = text.replace(/\bexecutionIntent\s*=\s*([a-zA-Z_]+)/gi, "执行意图：$1");

  // 指标统计与字段键名
  text = text.replace(/\bhits\s*=\s*(\d+)/gi, "检出 $1 个漏洞");
  text = text.replace(/\bdeletedCount\s*=\s*(\d+)/gi, "已删除 $1 条");
  text = text.replace(/\bretainedCount\s*=\s*(\d+)/gi, "已保留 $1 条");
  text = text.replace(/\bdiscovered\s*=\s*(\d+)/gi, "已发现 $1 项");
  text = text.replace(/\bimported\s*=\s*(\d+)/gi, "已导入 $1 项");
  text = text.replace(/\bupdated\s*=\s*(\d+)/gi, "已更新 $1 项");
  text = text.replace(/\bremoved\s*=\s*(\d+)/gi, "已移除 $1 项");
  text = text.replace(/\bdeletedPaths\s*=\s*(\d+)/gi, "已删除 $1 条路径");
  text = text.replace(/\bmissingPaths\s*=\s*(\d+)/gi, "缺失 $1 条路径");
  text = text.replace(/\bautomatedSteps\s*=\s*(\d+)/gi, "自动化步骤：$1 步");
  text = text.replace(/\badded\s*=\s*(\d+)/gi, "新增 $1 项漏洞");
  text = text.replace(/\bresolved\s*=\s*(\d+)/gi, "已修复 $1 项漏洞");
  text = text.replace(/\bpersistent\s*=\s*(\d+)/gi, "持续存在 $1 项漏洞");
  text = text.replace(/\bseverityChanged\s*=\s*(\d+)/gi, "等级变更 $1 项");
  text = text.replace(/\breoccurred\s*=\s*true/gi, "漏洞复现：是");
  text = text.replace(/\breoccurred\s*=\s*false/gi, "漏洞复现：否");
  text = text.replace(/\bpasses\s*=\s*(\d+)/gi, "通过次数：$1");
  text = text.replace(/\btargets\s*=\s*(\d+)/gi, "目标数：$1");

  text = text.replace(/\bscope\s*=/gi, "范围：");
  text = text.replace(/\btargetIds\s*=/gi, "目标列表：");
  text = text.replace(/\btaskIds\s*=/gi, "关联任务：");
  text = text.replace(/\bfindingIds\s*=/gi, "关联漏洞：");
  text = text.replace(/\btool\s*=/gi, "工具：");
  text = text.replace(/\bmodel disabled\b/gi, "模型服务未启用");
  text = text.replace(/\bmodel response unavailable\b/gi, "模型无响应");
  text = text.replace(/\bmodel unavailable\b/gi, "模型服务不可用");
  text = text.replace(/\bprovider\s*=\s*local-rule-fallback/gi, "服务源：本地规则兜底");
  text = text.replace(/\bprovider\s*=\s*local-rule/gi, "服务源：本地规则引擎");
  text = text.replace(/\bprovider\s*=\s*local-model/gi, "服务源：本地大模型");
  text = text.replace(/\bprovider\s*=\s*remote-api/gi, "服务源：远程接口");
  text = text.replace(/\bprovider\s*=/gi, "服务源：");
  text = text.replace(/\bprompt\s*=/gi, "提示词：");
  text = text.replace(/\berror\s*=/gi, "错误：");
  text = text.replace(/\breason\s*=/gi, "原因：");
  text = text.replace(/\bport\s*=/gi, "端口：");
  text = text.replace(/\bsource\s*=\s*nuclei/gi, "数据源：Nuclei");
  text = text.replace(/\bsource\s*=\s*afrog/gi, "数据源：Afrog");
  text = text.replace(/\bsource\s*=\s*xray/gi, "数据源：Xray");
  text = text.replace(/\bsource\s*=\s*msf/gi, "数据源：Metasploit");
  text = text.replace(/\bsource\s*=/gi, "数据源：");
  text = text.replace(/\bmode\s*=/gi, "模式：");

  text = text.replace(/\bcapturing\s*=\s*true/gi, "拦截开启");
  text = text.replace(/\bcapturing\s*=\s*false/gi, "拦截停止");
  text = text.replace(/\bmarked\s*=\s*true/gi, "已标记为重点流量");
  text = text.replace(/\bmarked\s*=\s*false/gi, "已取消重点标记");
  text = text.replace(/\benabled\s*=\s*true/gi, "已启用");
  text = text.replace(/\benabled\s*=\s*false/gi, "已停用");
  text = text.replace(/\bcleared\s*=\s*true/gi, "已清空");
  text = text.replace(/\bcleared\s*=\s*false/gi, "未清空");

  // 工具名称中文化
  Object.entries(AUDIT_TOOL_LABELS).forEach(([code, label]) => {
    text = text.replace(new RegExp(`\\b${code}\\b`, "g"), label);
  });

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
    CLARIFY: "需向用户澄清",
    EXECUTE: "执行安全方案",
    PLAN_ONLY: "生成待确认方案",
    AUTO: "自动",
    MANUAL: "手动",
    SINGLE: "单目标",
    ALL: "全部目标",
    SELECTED: "已选目标",
    BLACKLIST: "黑名单",
    WHITELIST: "白名单",
    SUFFIX: "后缀匹配",
    HOST: "域名匹配",
    PATH: "路径匹配",
  };
  Object.entries(tokenMap).forEach(([en, zh]) => {
    text = text.replace(new RegExp(`\\b${en}\\b`, "gi"), zh);
  });

  // key=value 形式残留的英文 key 也中文化
  text = text
    .replace(/\bstatus\s*=/gi, "状态：")
    .replace(/\baction\s*=/gi, "动作：")
    .replace(/\bdecision\s*=/gi, "决定：");

  return text;
}

export function formatAuditAction(action?: string): string {
  if (!action) return "未知操作";
  const key = String(action).trim().toUpperCase();
  return AUDIT_ACTION_LABELS[key] || "未知操作";
}

export function formatAuditResource(resource?: string): string {
  if (!resource) return "未指定";
  const key = String(resource).trim().toUpperCase();
  return AUDIT_RESOURCE_LABELS[key] || "未知资源";
}

export function formatAuditResult(result?: string): string {
  if (!result) return "未知";
  const key = String(result).trim().toUpperCase();
  return AUDIT_RESULT_META[key]?.label || "未知结果";
}

export function auditResultTagType(
  result?: string,
): "success" | "danger" | "warning" | "info" | "primary" {
  if (!result) return "info";
  const key = String(result).trim().toUpperCase();
  return AUDIT_RESULT_META[key]?.tagType || "info";
}
