package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * A service-identification scan reuses the ports the preceding probe found open instead of
 * re-sweeping the whole range.
 */
class TaskExecutionPortNarrowingTests {
  private final SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
  private final FindingRepository findingRepository = mock(FindingRepository.class);
  private final TargetService targetService = mock(TargetService.class);
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final SecurityToolRegistry registry = mock(SecurityToolRegistry.class);
  private final AuditService auditService = mock(AuditService.class);
  private final TaskSnapshotService snapshotService = mock(TaskSnapshotService.class);
  private final TaskProgressEventService progressEvents = mock(TaskProgressEventService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);

  private TaskExecutionService service;

  private void arrange(SecurityTask task, SecurityTool tool) throws Exception {
    when(authorization.callWithSystemAccess(any(java.util.concurrent.Callable.class)))
        .thenAnswer(invocation -> ((java.util.concurrent.Callable<?>) invocation.getArgument(0)).call());
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("http://192.168.1.10");
    when(taskRepository.findById(task.getId())).thenReturn(Optional.of(task));
    when(targetService.getCurrentlyAuthorized(7L)).thenReturn(target);
    when(registry.require("nmap_service_scan")).thenReturn(tool);
    when(tool.code()).thenReturn("nmap_service_scan");
    when(tool.execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class)))
        .thenReturn(new com.bachelor.toolbox.tool.ToolExecutionResult(
            "ok", Map.of(), List.of()));
    service =
        new TaskExecutionService(
            taskRepository,
            findingRepository,
            targetService,
            projectService,
            registry,
            auditService,
            new ObjectMapper(),
            snapshotService,
            new TaskExecutionControlService(1, 1),
            progressEvents,
            authorization);
  }

  private SecurityTask scanTask(String requestJson) {
    SecurityTask task = new SecurityTask();
    task.setId(500L);
    task.setProjectId(1L);
    task.setTargetId(7L);
    task.setToolCode("nmap_service_scan");
    task.setStatus("PENDING");
    task.setRequestJson(requestJson);
    task.setAuthorizationSnapshotHash("hash");
    return task;
  }

  private SecurityTask probe(long id, String openPortsJson) {
    SecurityTask probe = new SecurityTask();
    probe.setId(id);
    probe.setProjectId(1L);
    probe.setTargetId(7L);
    probe.setToolCode("tcp_ports");
    probe.setStatus("SUCCESS");
    // 真实落库结构：序列化后的 ToolExecutionResult，端口清单在 data.openPorts 下
    probe.setResultJson("{\"summary\":\"探测完成\",\"data\":{\"openPorts\":" + openPortsJson + "},\"findings\":[]}");
    return probe;
  }

  @Test
  void serviceScanNarrowsToPortsTheProbeFoundOpen() throws Exception {
    SecurityTask task = scanTask("{\"ports\":\"1-65535\",\"consumeOpenPorts\":true}");
    task.setDependencyTaskIds("[11]");
    SecurityTool tool = mock(SecurityTool.class);
    arrange(task, tool);
    when(taskRepository.findAllById(List.of(11L)))
        .thenReturn(List.of(probe(11L, "[80,443,8080]")));

    service.executeAsync(500L);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
    org.mockito.Mockito.verify(tool)
        .execute(any(AuthorizedTarget.class), captor.capture(), any(ToolExecutionObserver.class));
    assertThat(captor.getValue()).containsEntry("ports", "80,443,8080");
    // The hint itself must never reach the tool.
    assertThat(captor.getValue()).doesNotContainKey("consumeOpenPorts");
  }

  @Test
  void explicitPortsAreLeftAloneEvenWithTheHintSet() throws Exception {
    // The planner picked specific ports for a reason; the hint must not override that choice.
    SecurityTask task = scanTask("{\"ports\":\"443\",\"consumeOpenPorts\":true}");
    task.setDependencyTaskIds("[11]");
    SecurityTool tool = mock(SecurityTool.class);
    arrange(task, tool);
    when(taskRepository.findAllById(List.of(11L)))
        .thenReturn(List.of(probe(11L, "[80,443,8080]")));

    service.executeAsync(500L);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
    org.mockito.Mockito.verify(tool)
        .execute(any(AuthorizedTarget.class), captor.capture(), any(ToolExecutionObserver.class));
    assertThat(captor.getValue()).containsEntry("ports", "443");
  }

  @Test
  void workflowDispatchUsesSuccessDependencyIdsToNarrow() throws Exception {
    // Workflow-dispatched tasks record dependencies in successDependencyTaskIds, not
    // dependencyTaskIds. The narrowing must read that field too, otherwise the probe's
    // open ports never reach the service-identification scan.
    SecurityTask task = scanTask("{\"ports\":\"1-65535\",\"consumeOpenPorts\":true}");
    task.setDependencyTaskIds(null);
    task.setSuccessDependencyTaskIds("[11]");
    SecurityTool tool = mock(SecurityTool.class);
    arrange(task, tool);
    when(taskRepository.findAllById(List.of(11L)))
        .thenReturn(List.of(probe(11L, "[80,443,8080]")));

    service.executeAsync(500L);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
    org.mockito.Mockito.verify(tool)
        .execute(any(AuthorizedTarget.class), captor.capture(), any(ToolExecutionObserver.class));
    assertThat(captor.getValue()).containsEntry("ports", "80,443,8080");
    assertThat(captor.getValue()).doesNotContainKey("consumeOpenPorts");
  }

  @Test
  void convergenceLogStaysBoundedWhenTheProbeReportsEveryPort() throws Exception {
    // A target that answers on all 65535 ports must not produce a megabyte-long log line:
    // the execution log is capped and would otherwise bury the explanation itself.
    SecurityTask task = scanTask("{\"ports\":\"1-65535\",\"consumeOpenPorts\":true}");
    task.setDependencyTaskIds("[11]");
    SecurityTool tool = mock(SecurityTool.class);
    arrange(task, tool);
    StringBuilder all = new StringBuilder("[");
    for (int port = 1; port <= 65535; port++) all.append(port).append(port < 65535 ? "," : "");
    all.append("]");
    when(taskRepository.findAllById(List.of(11L))).thenReturn(List.of(probe(11L, all.toString())));

    service.executeAsync(500L);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
    org.mockito.Mockito.verify(tool)
        .execute(any(AuthorizedTarget.class), captor.capture(), any(ToolExecutionObserver.class));
    // 端口集合必须完整传入工具（由工具的 canonicalizeCompact 再压缩为区间）
    String ports = String.valueOf(captor.getValue().get("ports"));
    assertThat(ports.startsWith("1,2,3,")).isTrue();
    assertThat(ports.endsWith("65535")).isTrue();
  }

  @Test
  void noDependencyResultKeepsTheOriginalRequest() throws Exception {
    // A failed probe must not silently turn the sweep into a no-op.
    SecurityTask task = scanTask("{\"ports\":\"1-65535\",\"consumeOpenPorts\":true}");
    task.setDependencyTaskIds("[11]");
    SecurityTool tool = mock(SecurityTool.class);
    arrange(task, tool);
    when(taskRepository.findAllById(List.of(11L))).thenReturn(List.of());

    service.executeAsync(500L);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
    org.mockito.Mockito.verify(tool)
        .execute(any(AuthorizedTarget.class), captor.capture(), any(ToolExecutionObserver.class));
    assertThat(captor.getValue()).containsEntry("ports", "1-65535");
  }

  @Test
  void hintIsIgnoredWhenTheTaskDidNotOptIn() throws Exception {
    SecurityTask task = scanTask("{\"ports\":\"1-65535\"}");
    task.setDependencyTaskIds("[11]");
    SecurityTool tool = mock(SecurityTool.class);
    arrange(task, tool);
    when(taskRepository.findAllById(List.of(11L)))
        .thenReturn(List.of(probe(11L, "[80,443,8080]")));

    service.executeAsync(500L);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
    org.mockito.Mockito.verify(tool)
        .execute(any(AuthorizedTarget.class), captor.capture(), any(ToolExecutionObserver.class));
    assertThat(captor.getValue()).containsEntry("ports", "1-65535");
  }
}
