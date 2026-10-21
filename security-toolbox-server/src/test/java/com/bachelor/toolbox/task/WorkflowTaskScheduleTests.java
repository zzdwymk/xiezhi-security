package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Concurrency classification and execution-group scheduling (scheme B). */
class WorkflowTaskScheduleTests {

  // ---- tool profile classification -------------------------------------------------------

  @Test
  void lightReadOnlyProbesMayShareTheTarget() {
    assertThat(ToolConcurrency.profileOf("tcp_ports")).isEqualTo(ToolConcurrency.Profile.LIGHT);
    assertThat(ToolConcurrency.profileOf("http_headers")).isEqualTo(ToolConcurrency.Profile.LIGHT);
    assertThat(ToolConcurrency.profileOf("tls_config")).isEqualTo(ToolConcurrency.Profile.LIGHT);
    assertThat(ToolConcurrency.canRunConcurrently("tcp_ports", "http_headers")).isTrue();
    assertThat(ToolConcurrency.canRunConcurrently("tls_config", "http_security_check")).isTrue();
  }

  @Test
  void portSweepsAndCrawlersAreBarriersThatNeverBatch() {
    for (String tool : List.of("nmap_service_scan", "fscan_scan", "dir_scan", "nuclei_scan",
        "afrog_scan", "xray_scan", "zap_scan", "site_crawl", "msf_scan")) {
      assertThat(ToolConcurrency.isBarrier(tool)).as(tool).isTrue();
      assertThat(ToolConcurrency.canRunConcurrently(tool, "http_headers")).as(tool).isFalse();
    }
  }

  @Test
  void requestMutatingToolsAreBarriers() {
    assertThat(ToolConcurrency.profileOf("sqlmap_scan")).isEqualTo(ToolConcurrency.Profile.ATTACK);
    assertThat(ToolConcurrency.profileOf("zap_fuzz")).isEqualTo(ToolConcurrency.Profile.ATTACK);
    assertThat(ToolConcurrency.isBarrier("sqlmap_scan")).isTrue();
  }

  @Test
  void unknownToolDefaultsToBarrierSoNewToolsNeverRunConcurrently() {
    assertThat(ToolConcurrency.profileOf("some_future_tool"))
        .isEqualTo(ToolConcurrency.Profile.EXCLUSIVE);
    assertThat(ToolConcurrency.isBarrier("some_future_tool")).isTrue();
  }

  // ---- serial requirement combines risk gate and occupancy ------------------------------

  @Test
  void nonSafeRiskOrApprovalStillForcesSerialRegardlessOfTool() {
    assertThat(WorkflowTaskSchedule.requiresSerialExecution("CAUTION", false, "http_headers")).isTrue();
    assertThat(WorkflowTaskSchedule.requiresSerialExecution("SAFE", true, "http_headers")).isTrue();
  }

  @Test
  void safeButSweepingToolIsTreatedAsSerialEvenThoughRiskIsSafe() {
    // Nmap is labelled SAFE but a full-port sweep distorts any concurrent probe.
    assertThat(WorkflowTaskSchedule.requiresSerialExecution("SAFE", false, "nmap_service_scan"))
        .isTrue();
    assertThat(WorkflowTaskSchedule.requiresSerialExecution("SAFE", false, "http_headers"))
        .isFalse();
  }

  // ---- execution group assignment --------------------------------------------------------

  @Test
  void twoLightTasksInOneTopologyGroupBecomeParallelSiblings() {
    WorkflowTaskSchedule schedule = new WorkflowTaskSchedule();

    // Same topology group, both light read-only: they should share an execution group.
    WorkflowTaskSchedule.Scheduled first =
        schedule.schedule(1, "SAFE", false, List.of(), "tcp_ports");
    WorkflowTaskSchedule.Scheduled second =
        schedule.schedule(1, "SAFE", false, List.of(), "http_headers");

    assertThat(second.group()).isEqualTo(first.group());
    assertThat(second.serial()).isFalse();
    assertThat(first.serial()).isFalse();
  }

  @Test
  void aBarrierStartsANewGroupAndLaterTasksWaitForIt() {
    WorkflowTaskSchedule schedule = new WorkflowTaskSchedule();

    WorkflowTaskSchedule.Scheduled light =
        schedule.schedule(1, "SAFE", false, List.of(), "http_headers");
    WorkflowTaskSchedule.Scheduled sweep =
        schedule.schedule(1, "SAFE", false, List.of(), "nmap_service_scan");
    WorkflowTaskSchedule.Scheduled after =
        schedule.schedule(1, "SAFE", false, List.of(), "tls_config");

    assertThat(sweep.serial()).isTrue();
    assertThat(sweep.group()).isGreaterThan(light.group());
    // The task after a barrier must still run in a fresh group and depend on the barrier.
    assertThat(after.group()).isGreaterThan(sweep.group());
  }

  @Test
  void threeLightProbesShareOneGroupThenASweepBreaksIt() {
    WorkflowTaskSchedule schedule = new WorkflowTaskSchedule();
    int g1 = schedule.schedule(1, "SAFE", false, List.of(), "tcp_ports").group();
    int g2 = schedule.schedule(1, "SAFE", false, List.of(), "http_headers").group();
    int g3 = schedule.schedule(1, "SAFE", false, List.of(), "tls_config").group();
    int sweep = schedule.schedule(1, "SAFE", false, List.of(), "nmap_service_scan").group();

    assertThat(g2).isEqualTo(g1);
    assertThat(g3).isEqualTo(g1);
    assertThat(sweep).isGreaterThan(g1);
  }
}
