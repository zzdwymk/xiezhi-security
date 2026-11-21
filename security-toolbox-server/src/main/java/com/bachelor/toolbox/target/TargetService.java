package com.bachelor.toolbox.target;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TargetService {
  /** 创建目标且未指定授权端口时的默认范围；更新路径保留原值，不回落到该默认集合。 */
  private static final String DEFAULT_ALLOWED_PORTS = "80,443,3000,8080";

  private static final Pattern DOMAIN_PATTERN =
      Pattern.compile(
          "(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
  private static final Pattern IPV4_PATTERN =
      Pattern.compile(
          "^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
  private static final Pattern URL_PATTERN =
      Pattern.compile(
          "^(?i)https?://[a-zA-Z0-9.-]+(?::\\d{1,5})?(?:/[^\\s]*)?$");
  private static final Sort LIST_SORT =
      Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));

  private final AuthorizedTargetRepository repository;
  private final AuditService auditService;
  private final PortRangeParser portRangeParser;
  private final AssessmentProjectRepository projects;
  private final ProjectTargetRepository projectTargets;
  private final ProjectAuthorizationService authorization;
  private final int maxAuthorizedPorts;

  public TargetService(
      AuthorizedTargetRepository repository,
      AuditService auditService,
      PortRangeParser portRangeParser,
      AssessmentProjectRepository projects,
      ProjectTargetRepository projectTargets,
      ProjectAuthorizationService authorization,
      @Value("${toolbox.execution.max-authorized-ports:65535}") int maxAuthorizedPorts) {
    this.repository = repository;
    this.auditService = auditService;
    this.portRangeParser = portRangeParser;
    this.projects = projects;
    this.projectTargets = projectTargets;
    this.authorization = authorization;
    this.maxAuthorizedPorts = maxAuthorizedPorts;
  }

  public List<AuthorizedTarget> list() {
    if (authorization.isAdmin()) {
      return loadAll(pageable -> repository.findAll(pageable));
    }
    String owner = authorization.currentUsername();
    return loadAll(pageable -> repository.findAccessibleByProjectOwner(owner, pageable));
  }

  /** Keep the array API compatible while reading every accessible page, not only the first 1000. */
  private <T> List<T> loadAll(java.util.function.Function<Pageable, Page<T>> pageLoader) {
    List<T> result = new ArrayList<>();
    for (int page = 0; ; page++) {
      Page<T> batch =
          pageLoader.apply(
              PageRequests.bounded(
                  page,
                  PageRequests.MAX_PAGE_SIZE,
                  1,
                  PageRequests.MAX_PAGE_SIZE,
                  LIST_SORT));
      result.addAll(batch.getContent());
      if (!batch.hasNext()) {
        return List.copyOf(result);
      }
    }
  }

  public AuthorizedTarget get(Long id) {
    AuthorizedTarget target =
        repository.findById(id).orElseThrow(() -> new ApiException("授权目标不存在"));
    requireTargetAccess(target);
    return target;
  }

  public AuthorizedTarget getCurrentlyAuthorized(Long id) {
    return validateCurrentlyAuthorized(load(id));
  }

  public AuthorizedTarget getCurrentlyAuthorized(Long id, Long projectId) {
    authorization.requireAccess(projectId);
    return validateCurrentlyAuthorized(load(id));
  }

  public AuthorizedTarget lockForAgentExecution(Long id) {
    AuthorizedTarget target =
        repository
            .findByIdForUpdate(id)
            .orElseThrow(() -> new ApiException("授权目标不存在"));
    requireTargetAccess(target);
    return target;
  }

  private AuthorizedTarget load(Long id) {
    return repository.findById(id).orElseThrow(() -> new ApiException("授权目标不存在"));
  }

  private AuthorizedTarget validateCurrentlyAuthorized(AuthorizedTarget target) {
    Instant now = Instant.now();
    if (!target.isEnabled()) throw new ApiException("授权目标已停用");
    if (target.getAuthorizationValidFrom() != null
        && now.isBefore(target.getAuthorizationValidFrom())) throw new ApiException("目标授权尚未生效");
    if (target.getAuthorizationExpiresAt() != null
        && !now.isBefore(target.getAuthorizationExpiresAt())) throw new ApiException("目标授权已过期");
    return target;
  }

  @Transactional
  public AuthorizedTarget create(TargetRequest request) {
    if (request.projectId() == null) throw new ApiException("请先创建安全评估项目，并在项目下登记授权目标");
    authorization.requireManage(request.projectId());
    validateProjectAssignable(request.projectId());
    AuthorizedTarget target = new AuthorizedTarget();
    apply(target, request, true);
    AuthorizedTarget saved = repository.save(target);
    projectTargets.save(new ProjectTarget(request.projectId(), saved.getId()));
    auditService.record(
        "CREATE_TARGET",
        "TARGET",
        saved.getId(),
        "project=" + request.projectId() + ";" + saved.getTargetValue(),
        "SUCCESS");
    return saved;
  }

  private void validateProjectAssignable(Long projectId) {
    AssessmentProject project =
        projects
            .findById(projectId)
            .orElseThrow(() -> new ApiException("评估项目不存在"));
    String status = project.getStatus();
    if ("ARCHIVED".equals(status) || "COMPLETED".equals(status)) {
      throw new ApiException("项目已归档或已完成，无法新增授权目标");
    }
  }

  @Transactional
  public AuthorizedTarget update(Long id, TargetRequest request) {
    AuthorizedTarget target = get(id);
    requireTargetManage(target);
    if (request.projectId() != null) {
      authorization.requireManage(request.projectId());
      if (projectTargets.findByProjectIdAndTargetId(request.projectId(), id).isEmpty()) {
        throw new ApiException("目标不属于该评估项目");
      }
    }
    // Round 285：授权范围变更必须可追溯。原实现只记录目标地址，端口范围与启停状态的变化
    // 在审计里完全看不到，事后无法证明「谁在何时把授权范围放宽/收窄」。
    String portsBefore = target.getAllowedPorts();
    boolean enabledBefore = target.isEnabled();
    Instant validFromBefore = target.getAuthorizationValidFrom();
    Instant expiresAtBefore = target.getAuthorizationExpiresAt();
    apply(target, request, false);
    AuthorizedTarget saved = repository.save(target);
    auditService.record(
        "UPDATE_TARGET",
        "TARGET",
        saved.getId(),
        describeScopeChange(saved, portsBefore, enabledBefore, validFromBefore, expiresAtBefore),
        "SUCCESS");
    return saved;
  }

  /** 生成授权范围变更摘要；仅在授权边界字段实际变化时追加对应片段。 */
  static String describeScopeChange(
      AuthorizedTarget saved,
      String portsBefore,
      boolean enabledBefore,
      Instant validFromBefore,
      Instant expiresAtBefore) {
    StringBuilder detail = new StringBuilder(saved.getTargetValue());
    if (!java.util.Objects.equals(portsBefore, saved.getAllowedPorts())) {
      detail
          .append("; allowedPorts ")
          .append(portsBefore == null ? "-" : portsBefore)
          .append("→")
          .append(saved.getAllowedPorts() == null ? "-" : saved.getAllowedPorts());
    }
    if (enabledBefore != saved.isEnabled()) {
      detail.append("; enabled ").append(enabledBefore).append("→").append(saved.isEnabled());
    }
    // Round 286：授权时间窗同属授权边界，变更同样需要可举证。
    if (!java.util.Objects.equals(validFromBefore, saved.getAuthorizationValidFrom())) {
      detail
          .append("; validFrom ")
          .append(validFromBefore)
          .append("→")
          .append(saved.getAuthorizationValidFrom());
    }
    if (!java.util.Objects.equals(expiresAtBefore, saved.getAuthorizationExpiresAt())) {
      detail
          .append("; expiresAt ")
          .append(expiresAtBefore)
          .append("→")
          .append(saved.getAuthorizationExpiresAt());
    }
    return detail.toString();
  }

  @Transactional
  public void delete(Long id) {
    AuthorizedTarget target = get(id);
    requireTargetManage(target);
    projectTargets.deleteAll(projectTargets.findByTargetId(id));
    repository.delete(target);
    auditService.record("DELETE_TARGET", "TARGET", id, target.getTargetValue(), "SUCCESS");
  }

  private void requireTargetAccess(AuthorizedTarget target) {
    if (authorization.isAdmin()) {
      return;
    }
    if (!hasAccessibleProject(target)) {
      throw new ApiException("无权访问该授权目标");
    }
  }

  private void requireTargetManage(AuthorizedTarget target) {
    if (authorization.isAdmin()) {
      return;
    }
    var links = projectTargets.findByTargetId(target.getId());
    if (links.isEmpty()
        || links.stream()
            .anyMatch(
                link ->
                    projects.findById(link.getProjectId()).map(authorization::canAccess).orElse(false)
                        == false)) {
      throw new ApiException("无权管理该授权目标");
    }
  }

  private boolean hasAccessibleProject(AuthorizedTarget target) {
    return projectTargets.findByTargetId(target.getId()).stream()
        .map(ProjectTarget::getProjectId)
        .map(projects::findById)
        .flatMap(java.util.Optional::stream)
        .anyMatch(authorization::canAccess);
  }

  /**
   * Round 283：{@code enabled} 可空。创建时缺省启用；更新时缺省表示「保持原状态」。
   * 否则一次与启停无关的局部编辑会把运维已停用的目标静默重新启用，而
   * {@code validateCurrentlyAuthorized} 正是以 {@code enabled} 判断授权范围——
   * 等于把已移出授权范围的目标重新变为可扫描对象。
   *
   * <p>Round 284：{@code allowedPorts} 同理。{@code TargetPolicyService} 以该字段拦截
   * 「目标端口 X 不在授权端口范围内」，更新时若把空白值回落成默认集合，会把运维收窄过的端口
   * 授权静默放宽（例如只剩 443 的目标被放宽到 80/443/3000/8080）。故更新路径保持原值。
   */
  private void apply(AuthorizedTarget target, TargetRequest request, boolean creating) {
    target.setName(request.name().trim());
    String targetValue = request.targetValue().trim();
    String targetType = request.targetType().trim().toUpperCase();
    validateTargetValue(targetType, targetValue);
    target.setTargetValue(targetValue);
    target.setTargetType(targetType);
    target.setAuthorizationNote(request.authorizationNote().trim());
    String allowedPorts =
        request.allowedPorts() == null || request.allowedPorts().isBlank()
            ? (creating ? DEFAULT_ALLOWED_PORTS : target.getAllowedPorts())
            : request.allowedPorts().trim();
    target.setAllowedPorts(portRangeParser.canonicalizeCompact(allowedPorts, maxAuthorizedPorts));
    target.setEnabled(
        request.enabled() != null ? request.enabled() : (creating || target.isEnabled()));
    // Round 286：时间窗字段可空。更新时 null 表示「保持不变」——否则一次无关编辑会把
    // authorizationExpiresAt 清成 null，而 validateCurrentlyAuthorized 把 null 视为「无到期限制」，
    // 等于让已过期目标重新变成可扫描对象。清空必须是显式动作（clearAuthorizationWindow）。
    boolean clearWindow = Boolean.TRUE.equals(request.clearAuthorizationWindow());
    Instant validFrom =
        clearWindow
            ? null
            : request.authorizationValidFrom() != null
                ? request.authorizationValidFrom()
                : (creating ? null : target.getAuthorizationValidFrom());
    Instant expiresAt =
        clearWindow
            ? null
            : request.authorizationExpiresAt() != null
                ? request.authorizationExpiresAt()
                : (creating ? null : target.getAuthorizationExpiresAt());
    if (validFrom != null && expiresAt != null && !validFrom.isBefore(expiresAt))
      throw new ApiException("授权开始时间必须早于授权到期时间");
    target.setAuthorizationValidFrom(validFrom);
    target.setAuthorizationExpiresAt(expiresAt);
  }

  private void validateTargetValue(String targetType, String targetValue) {
    if (!"DOMAIN".equals(targetType) && !"IP".equals(targetType) && !"URL".equals(targetType)) {
      throw new ApiException("目标类型无效：仅支持 IP、URL 或 DOMAIN");
    }
    if ("DOMAIN".equals(targetType) && !DOMAIN_PATTERN.matcher(targetValue).matches()) {
      throw new ApiException("域名格式不正确：请填写不含空格、协议或路径的主机名");
    }
    if ("IP".equals(targetType) && !IPV4_PATTERN.matcher(targetValue).matches()) {
      throw new ApiException("IP 地址格式不正确：请填写标准的 IPv4 地址（如 192.168.1.1），不得包含协议、路径或末尾多余符号");
    }
    if ("URL".equals(targetType) && !URL_PATTERN.matcher(targetValue).matches()) {
      throw new ApiException("URL 格式不正确：请填写以 http:// 或 https:// 开头的合法 URL 地址");
    }
  }
}
