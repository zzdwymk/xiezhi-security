package com.bachelor.toolbox.target;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TargetService {
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
      return repository.findAll(PageRequests.firstPage(LIST_SORT)).getContent();
    }
    return repository
        .findAccessibleByProjectOwner(
            authorization.currentUsername(), PageRequests.firstPage(LIST_SORT))
        .getContent();
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
    AuthorizedTarget target = new AuthorizedTarget();
    apply(target, request);
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

  public AuthorizedTarget update(Long id, TargetRequest request) {
    AuthorizedTarget target = get(id);
    requireTargetManage(target);
    if (request.projectId() != null) {
      authorization.requireManage(request.projectId());
      if (projectTargets.findByProjectIdAndTargetId(request.projectId(), id).isEmpty()) {
        throw new ApiException("目标不属于该评估项目");
      }
    }
    apply(target, request);
    AuthorizedTarget saved = repository.save(target);
    auditService.record(
        "UPDATE_TARGET", "TARGET", saved.getId(), saved.getTargetValue(), "SUCCESS");
    return saved;
  }

  public void delete(Long id) {
    AuthorizedTarget target = get(id);
    requireTargetManage(target);
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

  private void apply(AuthorizedTarget target, TargetRequest request) {
    target.setName(request.name().trim());
    target.setTargetValue(request.targetValue().trim());
    target.setTargetType(request.targetType().trim().toUpperCase());
    target.setAuthorizationNote(request.authorizationNote().trim());
    String allowedPorts =
        request.allowedPorts() == null || request.allowedPorts().isBlank()
            ? "80,443,3000,8080"
            : request.allowedPorts().trim();
    target.setAllowedPorts(portRangeParser.canonicalizeCompact(allowedPorts, maxAuthorizedPorts));
    target.setEnabled(request.enabled() == null || request.enabled());
    if (request.authorizationValidFrom() != null
        && request.authorizationExpiresAt() != null
        && !request.authorizationValidFrom().isBefore(request.authorizationExpiresAt()))
      throw new ApiException("授权开始时间必须早于授权到期时间");
    target.setAuthorizationValidFrom(request.authorizationValidFrom());
    target.setAuthorizationExpiresAt(request.authorizationExpiresAt());
  }
}
