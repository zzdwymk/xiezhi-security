package com.bachelor.toolbox.operation;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecurityActionService {
  private static final int LIST_LIMIT = 1000;
  private static final Sort LIST_SORT =
      Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
  private static final Set<String> CATEGORIES =
      Set.of(
          "VULNERABILITY_VALIDATION",
          "CONTROLLED_EXPLOITATION",
          "PRIVILEGE_VALIDATION",
          "INTERNAL_ASSESSMENT",
          "PERSISTENCE_VALIDATION");
  private static final Set<String> RISK_LEVELS = Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL");
  private static final Set<String> APPROVAL_DECISIONS = Set.of("APPROVED", "REJECTED");
  private static final Set<String> ROLLBACK_STATUSES = Set.of("RUNNING", "COMPLETED", "FAILED");

  private static final String STATUS_PENDING_APPROVAL = "PENDING_APPROVAL";
  private static final String STATUS_APPROVED = "APPROVED";
  private static final String STATUS_RUNNING = "RUNNING";
  private static final String STATUS_COMPLETED = "COMPLETED";
  private static final String STATUS_ROLLED_BACK = "ROLLED_BACK";
  private static final long MAX_WINDOW_SECONDS = 8 * 60 * 60L;
  private static final int MAX_TITLE_LENGTH = 200;
  private static final int MAX_PURPOSE_LENGTH = 4000;
  private static final int MAX_PLAN_LENGTH = 4000;
  private static final int MAX_EVIDENCE_LENGTH = 8000;
  private static final int MAX_REASON_LENGTH = 4000;

  /*
   * 安全动作仅用于服务端允许清单记录，不是命令传输通道。即使请求绕过
   * Web 客户端，也必须在服务边界拒绝命令拼接和常见命令执行器。
   */
  private static final Pattern COMMAND_SYNTAX =
      Pattern.compile("(?s).*(?:&&|\\|\\||(?<!\\|)\\|(?!\\|)|;|`|\\$\\(|(^|\\s)[<>]).*");
  private static final Pattern COMMAND_TOKEN =
      Pattern.compile(
          "(?im)(?:(?:^|\\s)"
              + "(?:bash|sh|zsh|cmd(?:\\.exe)?|powershell(?:\\.exe)?|pwsh|python(?:3)?|perl|ruby|"
              + "nmap|nuclei|sqlmap|msfconsole)"
              + "(?=\\s+(?:--?|/)\\S+)"
              + "|(?:^|\\s)(?:curl|wget)(?=\\s+https?://)"
              + "|^\\s*(?:nc|netcat|meterpreter|whoami|chmod|chown|rm|del|format|reg|schtasks|sc)"
              + "(?:\\s|$))");
  private static final Pattern SECRET_ASSIGNMENT =
      Pattern.compile(
          "(?is).*(?:password|passwd|pwd|token|secret|api[_ -]?key|authorization|bearer|"
              + "private[_ -]?key|ntlm|user[_ -]?hash|cookie)\\s*[:=]\\s*\\S+.*");

  private final SecurityActionRepository repository;
  private final AssessmentProjectService projects;
  private final AuditService audit;

  public SecurityActionService(
      SecurityActionRepository repository, AssessmentProjectService projects, AuditService audit) {
    this.repository = repository;
    this.projects = projects;
    this.audit = audit;
  }

  public List<SecurityAction> list(Long projectId) {
    projects.get(projectId);
    return repository.findByProjectId(
        projectId, PageRequests.bounded(0, LIST_LIMIT, 1, LIST_LIMIT, LIST_SORT));
  }

  public SecurityAction get(Long projectId, Long id) {
    SecurityAction action = repository.findById(id).orElseThrow(() -> new ApiException("安全动作不存在"));
    if (!projectId.equals(action.getProjectId())) {
      throw new ApiException("安全动作不属于当前项目");
    }
    return action;
  }

  @Transactional
  public SecurityAction create(
      Long projectId, SecurityActionDtos.Create request, Authentication authentication) {
    requireCreateRequest(request);
    validateTarget(projectId, request.targetId());

    AssessmentProject project = projects.get(projectId);
    validateCategory(request.category());
    validateExecutionWindow(project, request.windowStart(), request.windowEnd());
    validateRelatedFinding(projectId, request.targetId(), request.findingId());
    validateSafetyBoundary(request.nonDestructive(), request.lateralMovement());
    validateCreateText(request);

    String riskLevel = normalizeRiskLevel(request.riskLevel());
    String requestedBy = requireApplicant(authentication);
    SecurityAction action = buildAction(projectId, request, riskLevel, requestedBy);

    SecurityAction saved = repository.save(action);
    audit.record(
        "REQUEST_SECURITY_ACTION", "PROJECT", projectId, "actionId=" + saved.getId(), "SUCCESS");
    return saved;
  }

  @Transactional
  public SecurityAction decide(
      Long projectId, Long id, SecurityActionDtos.Decision request, Authentication authentication) {
    if (request == null) {
      throw new ApiException("审批决定不能为空");
    }

    SecurityAction action = get(projectId, id);
    requireStatus(action, STATUS_PENDING_APPROVAL, "动作已完成审批");
    String approvedBy = requireIndependentApprover(action, authentication);
    String decision = normalizeDecision(request.decision());
    requireSafeText(request.comment(), "审批备注", MAX_REASON_LENGTH, false);

    action.setStatus(decision);
    action.setApprovedBy(approvedBy);
    action.setApprovedAt(Instant.now());
    action.setTerminationReason(trimNullable(request.comment()));

    audit.record(
        "DECIDE_SECURITY_ACTION",
        "PROJECT",
        projectId,
        "actionId=" + id + ",decision=" + decision,
        "SUCCESS");
    return repository.save(action);
  }

  @Transactional
  public SecurityAction start(Long projectId, Long id) {
    SecurityAction action = get(projectId, id);
    projects.validateProjectTarget(projectId, action.getTargetId());

    Instant now = Instant.now();
    requireStatus(action, STATUS_APPROVED, "动作尚未批准");
    ensurePersistedSafetyBoundary(action);
    ensureInsideExecutionWindow(action, now);

    action.setStatus(STATUS_RUNNING);
    action.setStartedAt(now);
    audit.record("START_SECURITY_ACTION", "PROJECT", projectId, "actionId=" + id, "SUCCESS");
    return repository.save(action);
  }

  @Transactional
  public SecurityAction complete(Long projectId, Long id, SecurityActionDtos.Complete request) {
    if (request == null) {
      throw new ApiException("完成记录不能为空");
    }

    SecurityAction action = get(projectId, id);
    requireStatus(action, STATUS_RUNNING, "动作未在执行中");
    requireSafeText(request.evidence(), "执行证据", MAX_EVIDENCE_LENGTH, false);
    requireSafeText(request.terminationReason(), "终止原因", MAX_REASON_LENGTH, false);

    action.setEvidence(trimNullable(request.evidence()));
    action.setTerminationReason(trimNullable(request.terminationReason()));
    action.setFinishedAt(Instant.now());
    action.setStatus(STATUS_COMPLETED);

    audit.record("COMPLETE_SECURITY_ACTION", "PROJECT", projectId, "actionId=" + id, "SUCCESS");
    return repository.save(action);
  }

  @Transactional
  public SecurityAction rollback(Long projectId, Long id, SecurityActionDtos.Rollback request) {
    if (request == null) {
      throw new ApiException("回滚记录不能为空");
    }

    SecurityAction action = get(projectId, id);
    if (!ROLLBACK_STATUSES.contains(action.getStatus())) {
      throw new ApiException("当前状态不允许回滚");
    }
    requireSafeText(request.evidence(), "回滚证据", MAX_EVIDENCE_LENGTH, false);
    requireSafeText(request.reason(), "回滚原因", MAX_REASON_LENGTH, true);

    action.setRollbackEvidence(trimNullable(request.evidence()));
    action.setTerminationReason(trimNullable(request.reason()));
    action.setFinishedAt(Instant.now());
    action.setStatus(STATUS_ROLLED_BACK);

    audit.record("ROLLBACK_SECURITY_ACTION", "PROJECT", projectId, "actionId=" + id, "SUCCESS");
    return repository.save(action);
  }

  private void requireCreateRequest(SecurityActionDtos.Create request) {
    if (request == null) {
      throw new ApiException("安全动作申请不能为空");
    }
  }

  private void validateTarget(Long projectId, Long targetId) {
    if (targetId == null) {
      throw new ApiException("必须指定授权目标");
    }
    projects.validateProjectTarget(projectId, targetId);
  }

  private void validateCategory(String category) {
    if (!CATEGORIES.contains(category)) {
      throw new ApiException("不支持的安全动作类型");
    }
  }

  private void validateExecutionWindow(
      AssessmentProject project, Instant windowStart, Instant windowEnd) {
    if (windowStart == null
        || windowEnd == null
        || !windowEnd.isAfter(windowStart)
        || windowEnd.isAfter(windowStart.plusSeconds(MAX_WINDOW_SECONDS))) {
      throw new ApiException("执行时间窗无效或超过8小时");
    }

    Instant authorizationFrom = project.getAuthorizationValidFrom();
    Instant authorizationTo = project.getAuthorizationExpiresAt();
    if (authorizationFrom == null || authorizationTo == null) {
      throw new ApiException("项目授权有效期无效");
    }
    if (windowStart.isBefore(authorizationFrom) || windowEnd.isAfter(authorizationTo)) {
      throw new ApiException("执行时间窗必须完全位于项目授权有效期内");
    }
  }

  private void validateRelatedFinding(Long projectId, Long targetId, Long findingId) {
    if (findingId == null) {
      return;
    }

    Finding finding =
        projects.projectFindings(projectId).stream()
            .filter(item -> findingId.equals(item.getId()))
            .findFirst()
            .orElseThrow(() -> new ApiException("关联漏洞不属于当前项目"));
    if (!targetId.equals(finding.getTargetId())) {
      throw new ApiException("关联漏洞与授权目标不一致");
    }
  }

  private void validateSafetyBoundary(Boolean nonDestructive, Boolean lateralMovement) {
    if (Boolean.TRUE.equals(lateralMovement)) {
      throw new ApiException("禁止未授权横向移动；请将每个目标显式加入项目后分别申请动作");
    }
    if (!Boolean.TRUE.equals(nonDestructive)) {
      throw new ApiException("当前系统仅允许非破坏性验证");
    }
  }

  private void validateCreateText(SecurityActionDtos.Create request) {
    requireSafeText(request.title(), "动作标题", MAX_TITLE_LENGTH, true);
    requireSafeText(request.purpose(), "验证目的", MAX_PURPOSE_LENGTH, true);
    requireSafeText(request.executionPlan(), "执行计划", MAX_PLAN_LENGTH, true);
    requireSafeText(request.rollbackPlan(), "回滚计划", MAX_PLAN_LENGTH, true);
  }

  private String normalizeRiskLevel(String riskLevel) {
    String normalized = riskLevel == null ? "MEDIUM" : riskLevel.trim().toUpperCase(Locale.ROOT);
    if (!RISK_LEVELS.contains(normalized)) {
      throw new ApiException("风险等级无效");
    }
    return normalized;
  }

  private String requireApplicant(Authentication authentication) {
    if (authentication == null
        || authentication.getName() == null
        || authentication.getName().isBlank()) {
      throw new ApiException("无法识别申请人");
    }
    return authentication.getName();
  }

  private SecurityAction buildAction(
      Long projectId, SecurityActionDtos.Create request, String riskLevel, String requestedBy) {
    SecurityAction action = new SecurityAction();
    action.setProjectId(projectId);
    action.setTargetId(request.targetId());
    action.setFindingId(request.findingId());
    action.setCategory(request.category());
    action.setTitle(request.title().trim());
    action.setPurpose(request.purpose().trim());
    action.setRiskLevel(riskLevel);
    action.setNonDestructive(true);
    action.setLateralMovement(false);
    action.setExecutionPlan(request.executionPlan().trim());
    action.setRollbackPlan(request.rollbackPlan().trim());
    action.setWindowStart(request.windowStart());
    action.setWindowEnd(request.windowEnd());
    action.setRequestedBy(requestedBy);
    return action;
  }

  private void requireStatus(SecurityAction action, String requiredStatus, String errorMessage) {
    if (!requiredStatus.equals(action.getStatus())) {
      throw new ApiException(errorMessage);
    }
  }

  private String requireIndependentApprover(SecurityAction action, Authentication authentication) {
    if (authentication == null
        || authentication.getName() == null
        || authentication.getName().equals(action.getRequestedBy())) {
      throw new ApiException("申请人与审批人必须分离");
    }
    return authentication.getName();
  }

  private String normalizeDecision(String decision) {
    String normalized = decision == null ? "REJECTED" : decision.trim().toUpperCase(Locale.ROOT);
    if (!APPROVAL_DECISIONS.contains(normalized)) {
      throw new ApiException("审批结果无效");
    }
    return normalized;
  }

  private void ensurePersistedSafetyBoundary(SecurityAction action) {
    if (!action.isNonDestructive() || action.isLateralMovement()) {
      throw new ApiException("动作不满足非破坏性和禁止横向移动的安全边界");
    }
  }

  private void ensureInsideExecutionWindow(SecurityAction action, Instant now) {
    if (now.isBefore(action.getWindowStart()) || now.isAfter(action.getWindowEnd())) {
      throw new ApiException("当前不在批准执行时间窗内");
    }
  }

  private void requireSafeText(String value, String name, int maxLength, boolean required) {
    if (value == null || value.isBlank()) {
      if (required) {
        throw new ApiException(name + "不能为空");
      }
      return;
    }

    String text = value.trim();
    if (text.length() > maxLength) {
      throw new ApiException(name + "长度不得超过" + maxLength + "个字符");
    }
    if (COMMAND_SYNTAX.matcher(text).matches() || COMMAND_TOKEN.matcher(text).find()) {
      throw new ApiException(name + "不得包含命令拼接符、重定向或命令执行语法");
    }
    if (SECRET_ASSIGNMENT.matcher(text).matches()) {
      throw new ApiException("禁止保存明文凭据、令牌、私钥或用户哈希值；仅保存脱敏摘要或密钥库引用");
    }
  }

  private String trimNullable(String value) {
    return value == null ? null : value.trim();
  }
}
