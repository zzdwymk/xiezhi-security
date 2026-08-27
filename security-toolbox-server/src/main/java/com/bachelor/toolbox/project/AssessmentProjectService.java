package com.bachelor.toolbox.project;

import com.bachelor.toolbox.audit.AuditLog;
import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingClassification;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AssessmentProjectService {
  private static final Sort LIST_SORT =
      Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
  private static final Set<String> STATUSES =
      Set.of("DRAFT", "ACTIVE", "PAUSED", "COMPLETED", "ARCHIVED");

  private final AssessmentProjectRepository projects;
  private final ProjectTargetRepository links;
  private final AuthorizedTargetRepository targets;
  private final AuditService audit;
  private final SecurityTaskRepository taskRepository;
  private final FindingRepository findingRepository;
  private final AuditLogRepository auditRepository;
  private final ProjectAuthorizationService authorization;

  public AssessmentProjectService(
      AssessmentProjectRepository projects,
      ProjectTargetRepository links,
      AuthorizedTargetRepository targets,
      AuditService audit,
      SecurityTaskRepository taskRepository,
      FindingRepository findingRepository,
      AuditLogRepository auditRepository,
      ProjectAuthorizationService authorization) {
    this.projects = projects;
    this.links = links;
    this.targets = targets;
    this.audit = audit;
    this.taskRepository = taskRepository;
    this.findingRepository = findingRepository;
    this.auditRepository = auditRepository;
    this.authorization = authorization;
  }

  public List<AssessmentProject> list() {
    if (authorization.isAdmin()) {
      return projects.findAll(PageRequests.firstPage(LIST_SORT)).getContent();
    }
    return projects
        .findByOwner(authorization.currentUsername(), PageRequests.firstPage(LIST_SORT))
        .getContent();
  }

  public AssessmentProject get(Long id) {
    return authorization.requireAccess(id);
  }

  @Transactional
  public AssessmentProject create(ProjectDtos.Create request) {
    validateDates(request.authorizationValidFrom(), request.authorizationExpiresAt());

    AssessmentProject project = createProject(request);
    AssessmentProject saved = projects.save(project);
    audit.record("CREATE_PROJECT", "PROJECT", saved.getId(), saved.getName(), "SUCCESS");
    return saved;
  }

  @Transactional
  public AssessmentProject update(Long id, ProjectDtos.Update request) {
    AssessmentProject project = get(id);
    applyUpdate(project, request);
    validateDates(project.getAuthorizationValidFrom(), project.getAuthorizationExpiresAt());
    return projects.save(project);
  }

  @Transactional
  public AssessmentProject updateStatus(Long id, String status) {
    validateStatus(status);

    AssessmentProject project = get(id);
    project.setStatus(status);
    AssessmentProject saved = projects.save(project);
    audit.record("UPDATE_PROJECT_STATUS", "PROJECT", id, status, "SUCCESS");
    return saved;
  }

  @Transactional
  public ProjectTarget addTarget(Long projectId, Long targetId) {
    get(projectId);
    validateTargetCanBeAdded(projectId, targetId);

    ProjectTarget link = links.save(new ProjectTarget(projectId, targetId));
    audit.record("ADD_PROJECT_TARGET", "PROJECT", projectId, "targetId=" + targetId, "SUCCESS");
    return link;
  }

  @Transactional
  public void removeTarget(Long projectId, Long targetId) {
    get(projectId);
    requireProjectTarget(projectId, targetId, "项目未包含该目标");

    links.deleteByProjectIdAndTargetId(projectId, targetId);
    audit.record("REMOVE_PROJECT_TARGET", "PROJECT", projectId, "targetId=" + targetId, "SUCCESS");
  }

  public List<ProjectTarget> targets(Long id) {
    get(id);
    return links.findByProjectId(id);
  }

  /**
   * 只校验项目与目标的绑定关系，不要求项目处于有效授权时间窗。 历史项目仍可用于 AI 对话和结果回顾；执行入口必须调用 {@link #validateProjectTarget(Long,
   * Long)}。
   */
  public void validateProjectTargetMembership(Long projectId, Long targetId) {
    get(projectId);
    requireProjectTarget(projectId, targetId, "目标不属于该评估项目");
  }

  public void validateProjectTarget(Long projectId, Long targetId) {
    AssessmentProject project = get(projectId);
    validateActiveProject(project);
    validateAuthorizationWindow(project, Instant.now());
    requireProjectTarget(projectId, targetId, "目标不属于该评估项目");
  }

  /** Serialize quota reservation and task creation for one project inside a transaction. */
  public AssessmentProject lockForAgentExecution(Long projectId) {
    authorization.requireAccess(projectId);
    return projects
        .findByIdForUpdate(projectId)
        .orElseThrow(() -> new ApiException("评估项目不存在"));
  }

  public ProjectDtos.Summary summary(Long id) {
    AssessmentProject project = get(id);
    List<SecurityTask> projectTasks = loadProjectTasks(id);
    List<Finding> projectFindings = loadProjectFindings(projectTasks);
    return buildSummary(id, project, projectTasks, projectFindings);
  }

  public List<SecurityTask> projectTasks(Long id) {
    get(id);
    return loadProjectTasks(id);
  }

  public List<Finding> projectFindings(Long id) {
    get(id);
    return loadProjectFindings(loadProjectTasks(id));
  }

  public List<AuditLog> projectAudits(Long id) {
    get(id);
    return auditRepository.findTop100ByResourceTypeAndResourceIdOrderByCreatedAtDesc(
        "PROJECT", String.valueOf(id));
  }

  private AssessmentProject createProject(ProjectDtos.Create request) {
    AssessmentProject project = new AssessmentProject();
    project.setName(request.name());
    project.setDescription(request.description());
    project.setAuthorizationStatement(request.authorizationStatement());
    project.setAuthorizationValidFrom(request.authorizationValidFrom());
    project.setAuthorizationExpiresAt(request.authorizationExpiresAt());
    project.setOwner(resolveCreatedOwner(request.owner()));
    project.setStatus("DRAFT");
    return project;
  }

  private void applyUpdate(AssessmentProject project, ProjectDtos.Update request) {
    if (request.name() != null) {
      project.setName(request.name());
    }
    if (request.description() != null) {
      project.setDescription(request.description());
    }
    if (request.authorizationStatement() != null) {
      project.setAuthorizationStatement(request.authorizationStatement());
    }
    if (request.authorizationValidFrom() != null) {
      project.setAuthorizationValidFrom(request.authorizationValidFrom());
    }
    if (request.authorizationExpiresAt() != null) {
      project.setAuthorizationExpiresAt(request.authorizationExpiresAt());
    }
    if (request.owner() != null
        && !authorization.isAdmin()
        && !request.owner().equals(project.getOwner())) {
      throw new ApiException("普通用户不能修改项目负责人");
    }
    if (request.owner() != null && authorization.isAdmin()) {
      project.setOwner(resolveOwner(request.owner()));
    }
  }

  private String resolveOwner(String owner) {
    if (owner == null || owner.isBlank()) {
      return authorization.currentUsername();
    }
    return owner.strip();
  }

  private String resolveCreatedOwner(String owner) {
    if (authorization.isAdmin()) {
      return resolveOwner(owner);
    }
    return authorization.currentUsername();
  }

  private void validateStatus(String status) {
    if (!STATUSES.contains(status)) {
      throw new ApiException("不支持的项目状态");
    }
  }

  private void validateTargetCanBeAdded(Long projectId, Long targetId) {
    if (!targets.existsById(targetId)) {
      throw new ApiException("授权目标不存在");
    }
    if (links.findByProjectIdAndTargetId(projectId, targetId).isPresent()) {
      throw new ApiException("目标已在项目中");
    }
  }

  private void requireProjectTarget(Long projectId, Long targetId, String errorMessage) {
    if (targetId == null || links.findByProjectIdAndTargetId(projectId, targetId).isEmpty()) {
      throw new ApiException(errorMessage);
    }
  }

  private void validateActiveProject(AssessmentProject project) {
    if (!"ACTIVE".equals(project.getStatus())) {
      throw new ApiException("项目未处于进行中状态");
    }
  }

  private void validateAuthorizationWindow(AssessmentProject project, Instant now) {
    if (now.isBefore(project.getAuthorizationValidFrom())
        || now.isAfter(project.getAuthorizationExpiresAt())) {
      throw new ApiException("项目授权已过期或尚未生效");
    }
  }

  private List<SecurityTask> loadProjectTasks(Long projectId) {
    return taskRepository.findAllByProjectIdOrderByCreatedAtAsc(projectId);
  }

  private List<Finding> loadProjectFindings(List<SecurityTask> projectTasks) {
    List<Long> taskIds = projectTasks.stream().map(SecurityTask::getId).toList();
    if (taskIds.isEmpty()) {
      return List.of();
    }
    return findingRepository.findAllByTaskIdInOrderByCreatedAtAsc(taskIds);
  }

  private ProjectDtos.Summary buildSummary(
      Long projectId,
      AssessmentProject project,
      List<SecurityTask> projectTasks,
      List<Finding> projectFindings) {
    long vulnerabilityCount = FindingClassification.vulnerabilityCount(projectFindings);
    long informationalCount = FindingClassification.informationalCount(projectFindings);
    long retestCount =
        projectTasks.stream().filter(task -> task.getSourceFindingId() != null).count();
    long auditCount =
        auditRepository.countByProjectId(projectId, String.valueOf(projectId));

    return new ProjectDtos.Summary(
        project,
        links.countByProjectId(projectId),
        projectTasks.size(),
        vulnerabilityCount,
        informationalCount,
        retestCount,
        auditCount);
  }

  private void validateDates(Instant from, Instant to) {
    if (from == null || to == null || !to.isAfter(from)) {
      throw new ApiException("授权有效期不合法");
    }
  }
}
