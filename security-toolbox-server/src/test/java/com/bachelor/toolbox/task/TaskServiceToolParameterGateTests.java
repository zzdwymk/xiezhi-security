package com.bachelor.toolbox.task;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 唯一执行入口的工具参数校验——Round 10 下沉验证。
 *
 * <p>目标：证明 {@code TaskService.create} 这个<strong>所有创建路径的唯一汇聚点</strong>会执行
 * {@code ToolParameterPolicy}，即 REST / invoke_endpoint / 流量建议等<strong>绕过 AI 能力层</strong>的路径
 * 也无法提交非法工具参数。这正是"单一事实来源"根治方案的核心断言。
 */
@DisplayName("TaskService 唯一入口工具参数校验（Round 10）")
class TaskServiceToolParameterGateTests {
  private final SecurityTaskRepository repository = mock(SecurityTaskRepository.class);
  private final TargetService targetService = mock(TargetService.class);
  private final SecurityToolRegistry registry = mock(SecurityToolRegistry.class);
  private final TaskExecutionService executionService = mock(TaskExecutionService.class);
  private final AuditService auditService = mock(AuditService.class);
  private final TaskSnapshotService snapshotService = mock(TaskSnapshotService.class);
  private final TaskExecutionControlService executionControl = mock(TaskExecutionControlService.class);
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final TaskProgressEventService progressEvents = mock(TaskProgressEventService.class);
  private TaskService service;

  @BeforeEach
  void setUp() {
    service = new TaskService(repository, targetService, registry, executionService, auditService,
        new ObjectMapper(), snapshotService, executionControl, projectService, progressEvents);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(3L);
    target.setTargetValue("192.168.222.158");
    target.setTargetType("IP");
    target.setAllowedPorts("80,443");
    target.setEnabled(true);
    when(targetService.getCurrentlyAuthorized(any(), any())).thenReturn(target);
    when(repository.save(any(SecurityTask.class))).thenAnswer(inv -> {
      SecurityTask t = inv.getArgument(0);
      if (t.getId() == null) t.setId(99L);
      return t;
    });
  }

  @Test
  @DisplayName("GATE-1 已知工具夹带未允许参数键 → 在 TaskService 层被拒（不依赖上游能力层）")
  void rejectsUnexpectedKeyAtExecutionEntry() {
    ApiException ex = assertThrows(ApiException.class, () -> service.create(
        new CreateTaskRequest(1L, 3L, "tcp_ports", Map.of("evil", 1))));
    // ToolParameterPolicy 的拒绝文案
    org.assertj.core.api.Assertions.assertThat(ex.getMessage()).contains("tcp_ports");
    verify(repository, never()).save(any());
    verify(executionService, never()).executeAsync(any());
  }

  @Test
  @DisplayName("GATE-2 已知工具枚举取值非法（nmap mode） → 被拒")
  void rejectsInvalidEnumAtExecutionEntry() {
    ApiException ex = assertThrows(ApiException.class, () -> service.create(
        new CreateTaskRequest(1L, 3L, "nmap_service_scan", Map.of("mode", "aggressive"))));
    org.assertj.core.api.Assertions.assertThat(ex.getMessage()).contains("mode");
    verify(repository, never()).save(any());
  }

  @Test
  @DisplayName("GATE-3 合法参数 → 通过唯一入口（对照组，不误拦）")
  void allowsValidParameters() throws Exception {
    SecurityTask saved = service.create(
        new CreateTaskRequest(1L, 3L, "tcp_ports", Map.of("ports", "80")));
    assertEquals("tcp_ports", saved.getToolCode());
    verify(repository).save(any(SecurityTask.class));
  }

  @Test
  @DisplayName("GATE-4 新增合法键（consumeOpenPorts / dir_scan.dictionary）→ 不误拒（漂移修复联动）")
  void allowsPreviouslyDriftedKeys() throws Exception {
    service.create(new CreateTaskRequest(1L, 3L, "nmap_service_scan",
        Map.of("ports", "80", "consumeOpenPorts", true)));
    service.create(new CreateTaskRequest(1L, 3L, "dir_scan", Map.of("dictionary", "common")));
    verify(repository, org.mockito.Mockito.atLeast(2)).save(any(SecurityTask.class));
  }
}
