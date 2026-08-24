package com.bachelor.toolbox.finding;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/findings")
public class FindingController {
  /** 归属过滤时一次性载入的任务 ID 上限，与任务列表上限保持一致 */
  private static final int ACCESSIBLE_TASK_LIMIT = 1000;

  private final FindingRepository repository;
  private final SecurityTaskRepository taskRepository;
  private final AuditService auditService;
  private final ProjectAuthorizationService authorization;

  public FindingController(
      FindingRepository repository,
      SecurityTaskRepository taskRepository,
      AuditService auditService,
      ProjectAuthorizationService authorization) {
    this.repository = repository;
    this.taskRepository = taskRepository;
    this.auditService = auditService;
    this.authorization = authorization;
  }

  @GetMapping
  public Page<Finding> list(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      @RequestParam(defaultValue = "") String query) {
    var pageable =
        PageRequests.bounded(page, size, 10, 100, Sort.by(Sort.Direction.DESC, "createdAt"));
    String keyword = query == null ? "" : query.trim();
    Specification<Finding> scope = accessibleScope();
    Specification<Finding> spec =
        keyword.isEmpty() ? scope : Specification.allOf(scope, buildSpecification(keyword));
    Page<Finding> result = repository.findAll(spec, pageable);
    populateProjectId(result.getContent());
    return result;
  }

  /**
   * 结果的可见范围。管理员可见全部；普通用户仅可见其可访问项目下任务产生的结果。
   * 返回 null 表示不附加限制（Specification.allOf 会忽略 null 判定）。
   */
  private Specification<Finding> accessibleScope() {
    if (authorization.isAdmin()) {
      return (root, criteriaQuery, builder) -> builder.conjunction();
    }
    List<Long> taskIds = accessibleTaskIds();
    if (taskIds.isEmpty()) {
      return (root, criteriaQuery, builder) -> builder.disjunction();
    }
    return (root, criteriaQuery, builder) -> root.get("taskId").in(taskIds);
  }

  /** 当前用户可访问项目下的全部任务 ID */
  private List<Long> accessibleTaskIds() {
    List<Long> projectIds =
        authorization.accessibleProjectIds();
    if (projectIds.isEmpty()) {
      return List.of();
    }
    return taskRepository.findAllByProjectIdIn(
            projectIds,
            PageRequests.bounded(0, ACCESSIBLE_TASK_LIMIT, 1, ACCESSIBLE_TASK_LIMIT,
                Sort.by(Sort.Direction.DESC, "id")))
        .stream()
        .map(SecurityTask::getId)
        .toList();
  }

  /**
   * 校验单条结果的归属：其所属任务必须在当前用户可访问的项目内。
   * 管理员不受限制。
   */
  private Finding requireAccessible(Long id, String notFoundMessage) {
    Finding finding = repository.findById(id).orElseThrow(() -> new ApiException(notFoundMessage));
    if (authorization.isAdmin()) {
      return finding;
    }
    SecurityTask task =
        finding.getTaskId() == null
            ? null
            : taskRepository.findById(finding.getTaskId()).orElse(null);
    if (task == null || task.getProjectId() == null) {
      throw new ApiException(notFoundMessage);
    }
    // 无权访问该项目时抛出，等同于不存在，避免通过错误信息探测他人数据
    authorization.requireAccess(task.getProjectId());
    return finding;
  }


  private Specification<Finding> buildSpecification(String keyword) {
    String pattern = "%" + keyword.toLowerCase(Locale.ROOT) + "%";
    Long numericKeyword = parseLong(keyword);
    return (root, criteriaQuery, builder) -> {
      List<Predicate> predicates = new ArrayList<>();
      for (String field :
          List.of("title", "severity", "sourceTool", "status", "ruleCode", "vulnerabilityCode")) {
        predicates.add(builder.like(builder.lower(root.get(field)), pattern));
      }
      if (numericKeyword != null) {
        predicates.add(builder.equal(root.get("targetId"), numericKeyword));
        predicates.add(builder.equal(root.get("taskId"), numericKeyword));
      }
      return builder.or(predicates.toArray(Predicate[]::new));
    };
  }

  private void populateProjectId(List<Finding> findings) {
    if (findings.isEmpty()) return;
    List<Long> taskIds =
        findings.stream().map(Finding::getTaskId).filter(Objects::nonNull).distinct().toList();
    if (taskIds.isEmpty()) return;
    Map<Long, Long> taskProject =
        taskRepository.findAllById(taskIds).stream()
            .collect(Collectors.toMap(SecurityTask::getId, SecurityTask::getProjectId));
    for (Finding finding : findings) {
      finding.setProjectId(taskProject.get(finding.getTaskId()));
    }
  }
  private Long parseLong(String value) {
    try {
      return Long.valueOf(value);
    } catch (NumberFormatException ignored) {
      return null;
    }
  }

  @PutMapping("/{id}/status")
  public Finding updateStatus(@PathVariable Long id, @RequestBody StatusRequest request) {
    String status = request.status() == null ? "" : request.status().trim().toUpperCase();
    if (!List.of("OPEN", "CONFIRMED", "FALSE_POSITIVE", "FIXED").contains(status)) {
      throw new ApiException("漏洞状态仅支持 OPEN、CONFIRMED、FALSE_POSITIVE、FIXED");
    }
    Finding finding = requireAccessible(id, "漏洞记录不存在");
    finding.setStatus(status);
    Finding saved = repository.save(finding);
    // 回填瞬态 projectId：否则前端以响应覆盖行数据后会丢失项目上下文，
    // 导致「生成后续验证路径」等依赖 projectId 的功能立即不可用。
    populateProjectId(List.of(saved));
    auditService.record("UPDATE_FINDING_STATUS", "FINDING", id, status, "SUCCESS");
    return saved;
  }

  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Transactional
  public void delete(@PathVariable Long id) {
    Finding finding = requireAccessible(id, "结果记录不存在");
    repository.delete(finding);
    auditService.record("DELETE_FINDING", "FINDING", id, finding.getTitle(), "SUCCESS");
  }

  /**
   * 清空结果。属破坏性操作，已在 SecurityConfig 中限定为管理员；
   * 此处再次校验，避免安全配置调整后失去保护。
   */
  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Transactional
  public void clear() {
    if (!authorization.isAdmin()) {
      throw new ApiException("仅管理员可以清空结果");
    }
    long deletedCount = repository.count();
    repository.deleteAllInBatch();
    auditService.record(
        "CLEAR_FINDINGS", "FINDING", null, "deletedCount=" + deletedCount, "SUCCESS");
  }

  public record StatusRequest(String status) {}
}
