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

  /** Round 318：按项目串行化目标创建，关闭"先查后写"的并发窗口。 */
  private final java.util.concurrent.ConcurrentHashMap<Long, Object> projectLocks =
      new java.util.concurrent.ConcurrentHashMap<>();
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
    // Round 318：重复校验是"先查后写"，并发请求会同时通过检查各自写入。按项目串行化整个创建过程，
    // 让"检查 + 保存 + 建立项目关联"成为一个临界区（单机桌面部署，无需分布式锁）。
    synchronized (projectLocks.computeIfAbsent(request.projectId(), key -> new Object())) {
      return createLocked(request);
    }
  }

  private AuthorizedTarget createLocked(TargetRequest request) {
    authorization.requireManage(request.projectId());
    validateProjectAssignable(request.projectId());
    // Round 316：同一项目内不允许重复登记相同目标地址（实测原实现可连续创建两条完全相同的授权目标）。
    ensureNoDuplicateTarget(request.projectId(), request.targetValue(), null);
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

  /** 目标更新涉及的项目集合：请求声明的项目，或目标已关联的全部项目。 */
  private java.util.List<Long> projectIdsForUpdate(Long targetId, TargetRequest request) {
    java.util.List<Long> ids = new java.util.ArrayList<>();
    if (request != null && request.projectId() != null) {
      ids.add(request.projectId());
    } else {
      var links = projectTargets.findByTargetId(targetId);
      if (links != null) links.forEach(link -> ids.add(link.getProjectId()));
    }
    return ids;
  }

  /** 按项目 id 排序后嵌套加锁，避免不同更新顺序造成死锁。 */
  private <T> T withProjectLocks(java.util.List<Long> projectIds, java.util.function.Supplier<T> action) {
    java.util.List<Long> sorted =
        projectIds == null
            ? java.util.List.of()
            : projectIds.stream().distinct().sorted().collect(java.util.stream.Collectors.toList());
    return withProjectLocksAt(sorted, 0, action);
  }

  private <T> T withProjectLocksAt(
      java.util.List<Long> sorted, int index, java.util.function.Supplier<T> action) {
    if (index >= sorted.size()) return action.get();
    synchronized (projectLocks.computeIfAbsent(sorted.get(index), key -> new Object())) {
      return withProjectLocksAt(sorted, index + 1, action);
    }
  }

  /** 同项目内重复的授权目标不会带来任何额外授权信息，只会造成审计歧义与重复维护。 */
  private void ensureNoDuplicateTarget(Long projectId, String targetValue, Long excludeTargetId) {
    String incoming = normalizeTargetValue(targetValue);
    if (incoming.isEmpty()) return;
    var links = projectTargets.findByProjectId(projectId);
    if (links == null) return;
    for (ProjectTarget link : links) {
      if (excludeTargetId != null && excludeTargetId.equals(link.getTargetId())) continue;
      repository
          .findById(link.getTargetId())
          .filter(existing -> incoming.equals(normalizeTargetValue(existing.getTargetValue())))
          .ifPresent(
              existing -> {
                throw new ApiException("该评估项目下已存在相同目标地址");
              });
    }
  }

  /** 更新时按请求声明的项目（或目标已关联的全部项目）做重复校验。 */
  private void ensureUpdateNoDuplicate(Long targetId, TargetRequest request) {
    if (request.targetValue() == null) return;
    java.util.List<Long> projectIds = new java.util.ArrayList<>();
    if (request.projectId() != null) {
      projectIds.add(request.projectId());
    } else {
      projectTargets.findByTargetId(targetId).forEach(link -> projectIds.add(link.getProjectId()));
    }
    for (Long projectId : projectIds) {
      ensureNoDuplicateTarget(projectId, request.targetValue(), targetId);
    }
  }

  private static String normalizeTargetValue(String value) {
    if (value == null) return "";
    String normalized = value.trim().toLowerCase(java.util.Locale.ROOT);
    while (normalized.endsWith("/")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized;
  }

  private void validateProjectAssignable(Long projectId) {    AssessmentProject project =
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
    // Round 319：更新路径与创建一样是"先查后写"，并发改指到同一地址会产生重复目标。按相关项目加锁。
    return withProjectLocks(projectIdsForUpdate(id, request), () -> doUpdate(id, request));
  }

  private AuthorizedTarget doUpdate(Long id, TargetRequest request) {
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
    // Round 291：把授权目标改指到别处（或篡改授权说明文字）同样必须留痕。
    // 原实现只记录**新** targetValue，事后无法证明「授权范围被改写过」。
    String targetValueBefore = target.getTargetValue();
    String authorizationNoteBefore = target.getAuthorizationNote();
    // Round 317：改指到同项目已存在的目标地址同样必须拒绝（R316 只覆盖了创建路径）。
    ensureUpdateNoDuplicate(id, request);
    apply(target, request, false);
    AuthorizedTarget saved;
    try {
      saved = repository.save(target);
      // 立刻 flush，让 @Version 校验在审计写入之前发生。
      repository.flush();
    } catch (org.springframework.dao.OptimisticLockingFailureException conflict) {
      // Round 287：并发编辑同一目标时拒绝后写者，避免用旧快照覆盖他人的授权边界修改。
      throw new ApiException("该授权目标已被其他操作修改，请刷新后重新提交");
    }
    auditService.record(
        "UPDATE_TARGET",
        "TARGET",
        saved.getId(),
        describeScopeChange(
            saved,
            targetValueBefore,
            authorizationNoteBefore,
            portsBefore,
            enabledBefore,
            validFromBefore,
            expiresAtBefore),
        "SUCCESS");
    return saved;
  }

  /** 审计明细中的长文本裁剪：保留足够辨识的前缀，避免一条审计被整段授权说明撑爆。 */
  private static String clipForAudit(String value) {
    if (value == null) return "-";
    String trimmed = value.trim();
    if (trimmed.isEmpty()) return "-";
    int max = 120;
    return trimmed.length() <= max ? trimmed : trimmed.substring(0, max) + "…";
  }

  /** 生成授权范围变更摘要；仅在授权边界字段实际变化时追加对应片段。 */
  static String describeScopeChange(
      AuthorizedTarget saved,
      String targetValueBefore,
      String authorizationNoteBefore,
      String portsBefore,
      boolean enabledBefore,
      Instant validFromBefore,
      Instant expiresAtBefore) {
    StringBuilder detail = new StringBuilder(saved.getTargetValue());
    // Round 291：改指授权目标 = 改写授权对象本身，必须留旧值。
    if (!java.util.Objects.equals(targetValueBefore, saved.getTargetValue())) {
      detail
          .append("; targetValue ")
          .append(targetValueBefore == null ? "-" : targetValueBefore)
          .append("→")
          .append(saved.getTargetValue() == null ? "-" : saved.getTargetValue());
    }
    // Round 291：授权说明是"已获授权"的书面依据，被改写同样要可追溯（裁剪长度防审计膨胀）。
    String noteAfter = saved.getAuthorizationNote();
    if (!java.util.Objects.equals(authorizationNoteBefore, noteAfter)) {
      detail
          .append("; authorizationNote ")
          .append(clipForAudit(authorizationNoteBefore))
          .append("→")
          .append(clipForAudit(noteAfter));
    }
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
    // Round 293：删除后目标行不复存在，审计若只留地址，授权边界（端口/启停/时间窗/授权说明）
    // 就永久丢失，事后无法证明"被删掉的那份授权究竟覆盖了什么"。故在删除前取全量快照。
    String snapshot = describeDeletedTarget(target);
    projectTargets.deleteAll(projectTargets.findByTargetId(id));
    repository.delete(target);
    auditService.record("DELETE_TARGET", "TARGET", id, snapshot, "SUCCESS");
  }

  /** 删除审计用的授权快照（目标行删除后不可再查）。 */
  private static String describeDeletedTarget(AuthorizedTarget target) {
    return target.getTargetValue()
        + "; type="
        + target.getTargetType()
        + "; ports="
        + target.getAllowedPorts()
        + "; enabled="
        + target.isEnabled()
        + "; validFrom="
        + target.getAuthorizationValidFrom()
        + "; expiresAt="
        + target.getAuthorizationExpiresAt()
        + "; note="
        + clipForAudit(target.getAuthorizationNote());
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



