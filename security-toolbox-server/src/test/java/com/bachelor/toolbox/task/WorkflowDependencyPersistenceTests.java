package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

@DataJpaTest(properties = {
    "spring.datasource.url=jdbc:h2:mem:workflow-dependency;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "spring.jpa.show-sql=false"
})
class WorkflowDependencyPersistenceTests {
  @Autowired private SecurityTaskRepository tasks;
  @Autowired private WorkflowRunRepository runs;

  @Test
  void activatesExactlyOnceAndRetainsSeparateGraphPrerequisites() {
    WorkflowRun run = run("RUNNING");
    SecurityTask task = blocked(run.getId());
    task.setDependencyTaskIds("[101,102]");
    task.setSuccessDependencyTaskIds("[101]");
    task = tasks.saveAndFlush(task);

    assertThat(tasks.activateBlockedWorkflowTask(task.getId(), "ready", Instant.now())).isEqualTo(1);
    assertThat(tasks.activateBlockedWorkflowTask(task.getId(), "again", Instant.now())).isZero();
    SecurityTask saved = tasks.findById(task.getId()).orElseThrow();
    assertThat(saved.getStatus()).isEqualTo("PENDING");
    assertThat(saved.getDependencyTaskIds()).isEqualTo("[101,102]");
    assertThat(saved.getSuccessDependencyTaskIds()).isEqualTo("[101]");
  }

  @Test
  void aCancellationAfterTheSchedulerReadCannotBeResurrected() {
    SecurityTask task = tasks.saveAndFlush(blocked(run("RUNNING").getId()));
    Long readWhileBlocked = task.getId();
    task.setStatus("CANCELLED");
    task.setTerminationReason("CANCELLED");
    task.setFinishedAt(Instant.now());
    tasks.saveAndFlush(task);

    assertThat(tasks.activateBlockedWorkflowTask(readWhileBlocked, "ready", Instant.now())).isZero();
    SecurityTask saved = tasks.findById(task.getId()).orElseThrow();
    assertThat(saved.getStatus()).isEqualTo("CANCELLED");
    assertThat(saved.getTerminationReason()).isEqualTo("CANCELLED");
    assertThat(saved.getFinishedAt()).isNotNull();
  }

  @Test
  void stoppingRunCannotUnlockAnOtherwiseBlockedTask() {
    WorkflowRun run = run("RUNNING");
    SecurityTask task = tasks.saveAndFlush(blocked(run.getId()));
    run.setStatus("STOPPING");
    runs.saveAndFlush(run);

    assertThat(tasks.activateBlockedWorkflowTask(task.getId(), "ready", Instant.now())).isZero();
    assertThat(tasks.findById(task.getId()).orElseThrow().getStatus()).isEqualTo("BLOCKED");
  }

  @Test
  void missingRunCannotUnlockButLegacyUnboundTaskCan() {
    SecurityTask missing = tasks.saveAndFlush(blocked(99999L));
    SecurityTask legacy = tasks.saveAndFlush(blocked(null));

    assertThat(tasks.activateBlockedWorkflowTask(missing.getId(), "ready", Instant.now())).isZero();
    assertThat(tasks.activateBlockedWorkflowTask(legacy.getId(), "ready", Instant.now())).isEqualTo(1);
  }

  private WorkflowRun run(String status) {
    WorkflowRun run = new WorkflowRun();
    run.setProjectId(7L);
    run.setTargetId(9L);
    run.setWorkflowId("local-workflow-fixture");
    run.setWorkflowRevision(1L);
    run.setWorkflowDigest("sha256:" + "a".repeat(64));
    run.setSpecJson("{}");
    run.setStatus(status);
    return runs.saveAndFlush(run);
  }

  private SecurityTask blocked(Long runId) {
    SecurityTask task = new SecurityTask();
    task.setProjectId(7L);
    task.setTargetId(9L);
    task.setToolCode("http_headers");
    task.setWorkflowRunId(runId);
    task.setStatus("BLOCKED");
    return task;
  }
}
