package com.bachelor.toolbox.operation;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.auth.UserRepository;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import java.time.Instant;
import java.util.List;
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
  private static final Set<String> ROLLBACK_STATUSES = Set.of("RUNNING", "COMPLETED", "FAILED");

  private static final String STATUS_APPROVED = "APPROVED";
  private static final String STATUS_RUNNING = "RUNNING";
  private static final String STATUS_COMPLETED = "COMPLETED";
  private static final String STATUS_ROLLED_BACK = "ROLLED_BACK";
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
  private final TargetService targets;
  private final AuditService audit;

  public SecurityActionService(
      SecurityActionRepository repository,
      AssessmentProjectService projects,
      TargetService targets,
      AuditService audit,
      UserRepository users) {
    this.repository = repository;
    this.projects = projects;
    this.targets = targets;
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
    projects.get(projectId);
    throw new ApiException("高风险行动申请已合并，请由 AI 提交方案并在执行确认与审计中确认执行");
  }

  @Transactional
  public SecurityAction decide(
      Long projectId, Long id, SecurityActionDtos.Decision request, Authentication authentication) {
    projects.get(projectId);
    get(projectId, id);
    throw new ApiException("历史高风险行动不再支持审批，请由 AI 重新提交方案并确认执行");
  }

  @Transactional
  public SecurityAction start(Long projectId, Long id) {
    SecurityAction action = get(projectId, id);
    projects.validateProjectTarget(projectId, action.getTargetId());
    targets.getCurrentlyAuthorized(action.getTargetId(), projectId);

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

  private void requireStatus(SecurityAction action, String requiredStatus, String errorMessage) {
    if (!requiredStatus.equals(action.getStatus())) {
      throw new ApiException(errorMessage);
    }
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
