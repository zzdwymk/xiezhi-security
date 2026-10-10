package com.bachelor.toolbox.finding;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.List;
import java.time.Instant;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

@DataJpaTest(showSql = false, properties = {
    "spring.datasource.url=jdbc:h2:mem:finding-task-filter;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
    "spring.jpa.hibernate.ddl-auto=create-drop"
})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class FindingTaskFilterPersistenceTests {
  @Autowired private FindingRepository findings;
  @Autowired private SecurityTaskRepository tasks;
  @Autowired private EntityManager entityManager;
  private ProjectAuthorizationService authorization;
  private FindingController controller;

  @BeforeEach
  void setUp() {
    authorization = mock(ProjectAuthorizationService.class);
    controller = new FindingController(findings, tasks, mock(AuditService.class), authorization);
  }

  @Test
  void taskFilterAppliesBeforePaginationAndCountsOnlyItsFindings() {
    when(authorization.isAdmin()).thenReturn(true);
    SecurityTask selected = task(10L);
    SecurityTask other = task(20L);
    for (int i = 0; i < 13; i++) {
      finding(selected, "selected same title", "HIGH");
      finding(other, "other " + i, "HIGH");
    }

    // Deliberately force ties: database ordering must still be stable across pages.
    entityManager.createQuery("update Finding f set f.createdAt = :time")
        .setParameter("time", Instant.parse("2026-10-04T00:00:00Z")).executeUpdate();
    entityManager.clear();
    for (String sort : new String[] {null, "id-asc", "id-desc", "time-asc", "time-desc",
        "sev-asc", "sev-desc", "title-asc"}) {
      var first = controller.list(0, 10, "", null, null, null, null, sort, selected.getId());
      var second = controller.list(1, 10, "", null, null, null, null, sort, selected.getId());
      assertThat(first.getTotalElements()).isEqualTo(13);
      assertThat(first.getTotalPages()).isEqualTo(2);
      assertThat(first.getContent()).hasSize(10).allSatisfy(finding -> {
        assertThat(finding.getTaskId()).isEqualTo(selected.getId());
        assertThat(finding.getProjectId()).isEqualTo(10L);
      });
      assertThat(second.getContent()).hasSize(3).allSatisfy(finding ->
          assertThat(finding.getTaskId()).isEqualTo(selected.getId()));
      assertThat(second.getContent()).extracting(Finding::getId)
          .doesNotContainAnyElementsOf(first.getContent().stream().map(Finding::getId).toList());
    }
  }

  @Test
  void explicitTaskFilterCannotExposeFindingsFromAnInaccessibleProject() {
    when(authorization.accessibleProjectIds()).thenReturn(List.of(10L));
    SecurityTask allowed = task(10L);
    SecurityTask hidden = task(20L);
    finding(allowed, "shared title", "HIGH");
    finding(hidden, "shared title", "HIGH");

    assertThat(controller.list(0, 10, "", null, null, null, null, null, null)
        .getContent()).extracting(Finding::getTaskId).containsExactly(allowed.getId());
    var denied = controller.list(0, 10, "shared", hidden.getTargetId(), "HIGH", "OPEN",
        "vulnerability", "id-asc", hidden.getId());
    assertThat(denied.getContent()).isEmpty();
    assertThat(denied.getTotalElements()).isZero();

    when(authorization.accessibleProjectIds()).thenReturn(List.of());
    assertThat(controller.list(0, 10, "", null, null, null, null, null, allowed.getId())
        .getTotalElements()).isZero();
  }

  @Test
  void taskFilterIntersectsSearchAndSeverityInsteadOfReplacingThem() {
    when(authorization.isAdmin()).thenReturn(true);
    SecurityTask selected = task(10L);
    SecurityTask other = task(10L);
    Finding expected = finding(selected, "matching issue", "HIGH");
    finding(selected, "matching baseline", "LOW");
    finding(selected, "unrelated issue", "HIGH");
    finding(other, "matching issue", "HIGH");

    assertThat(controller.list(0, 10, "matching", selected.getTargetId(), "HIGH", "OPEN",
        "vulnerability", "id-asc", selected.getId()).getContent())
        .extracting(Finding::getId).containsExactly(expected.getId());
    assertThat(controller.list(0, 10, "", null, null, null, null, null, Long.MAX_VALUE)
        .getTotalElements()).isZero();
  }

  private SecurityTask task(Long projectId) {
    SecurityTask task = new SecurityTask();
    task.setProjectId(projectId);
    task.setTargetId(100L);
    task.setToolCode("nuclei_scan");
    task.setStatus("SUCCESS");
    return tasks.saveAndFlush(task);
  }

  private Finding finding(SecurityTask task, String title, String severity) {
    Finding finding = new Finding();
    finding.setTaskId(task.getId());
    finding.setTargetId(task.getTargetId());
    finding.setTitle(title);
    finding.setSeverity(severity);
    finding.setSourceTool(task.getToolCode());
    return findings.saveAndFlush(finding);
  }
}
