package com.bachelor.toolbox.finding;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
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
  private final FindingRepository repository;
  private final SecurityTaskRepository taskRepository;
  private final AuditService auditService;

  public FindingController(
      FindingRepository repository, SecurityTaskRepository taskRepository, AuditService auditService) {
    this.repository = repository;
    this.taskRepository = taskRepository;
    this.auditService = auditService;
  }

  @GetMapping
  public Page<Finding> list(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      @RequestParam(defaultValue = "") String query) {
    var pageable =
        PageRequests.bounded(page, size, 10, 100, Sort.by(Sort.Direction.DESC, "createdAt"));
    String keyword = query == null ? "" : query.trim();
    Page<Finding> result =
        keyword.isEmpty()
            ? repository.findAll(pageable)
            : repository.findAll(buildSpecification(keyword), pageable);
    populateProjectId(result.getContent());
    return result;
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
    Finding finding = repository.findById(id).orElseThrow(() -> new ApiException("漏洞记录不存在"));
    finding.setStatus(status);
    Finding saved = repository.save(finding);
    auditService.record("UPDATE_FINDING_STATUS", "FINDING", id, status, "SUCCESS");
    return saved;
  }

  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Transactional
  public void delete(@PathVariable Long id) {
    Finding finding = repository.findById(id).orElseThrow(() -> new ApiException("结果记录不存在"));
    repository.delete(finding);
    auditService.record("DELETE_FINDING", "FINDING", id, finding.getTitle(), "SUCCESS");
  }

  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Transactional
  public void clear() {
    long deletedCount = repository.count();
    repository.deleteAllInBatch();
    auditService.record(
        "CLEAR_FINDINGS", "FINDING", null, "deletedCount=" + deletedCount, "SUCCESS");
  }

  public record StatusRequest(String status) {}
}
