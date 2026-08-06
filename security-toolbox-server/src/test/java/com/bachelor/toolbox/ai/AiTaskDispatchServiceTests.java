package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AiTaskDispatchServiceTests {
  private final AiPlanningService planningService = mock(AiPlanningService.class);
  private final TargetService targetService = mock(TargetService.class);
  private final TargetPolicyService targetPolicyService = mock(TargetPolicyService.class);
  private final SecurityToolRegistry toolRegistry = mock(SecurityToolRegistry.class);
  private final TaskService taskService = mock(TaskService.class);
  private final AuditService auditService = mock(AuditService.class);
  private final PortRangeParser portRangeParser = new PortRangeParser();
  private AiTaskDispatchService service;
  private AuthorizedTarget target;

  @BeforeEach
  void setUp() {
    service =
        new AiTaskDispatchService(
            planningService,
            targetService,
            targetPolicyService,
            toolRegistry,
            taskService,
            auditService,
            portRangeParser,
            20,
            65535);
    target = new AuthorizedTarget();
    target.setId(7L);
    target.setEnabled(true);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts("80,443,8080");
    when(targetService.get(7L)).thenReturn(target);
  }

  @Test
  void conversationalResponseCreatesNoTask() throws Exception {
    AiPlanRequest request = new AiPlanRequest(7L, "你好");
    when(planningService.plan(request))
        .thenReturn(new AiPlanResponse("test", "test-model", "你好！", false, List.of()));

    AiDispatchResponse response = service.dispatch(request);

    assertEquals(0, response.taskCount());
    assertEquals(List.of(), response.taskIds());
    verify(taskService, never()).create(any(CreateTaskRequest.class));
  }

  @Test
  void dispatchesValidatedPlanAndCanonicalizesAuthorizedPorts() throws Exception {
    AiPlanRequest request = new AiPlanRequest(7L, "scan selected ports");
    when(planningService.plan(request))
        .thenReturn(
            new AiPlanResponse(
                "test",
                "test-model",
                "safe plan",
                true,
                List.of(
                    new AiPlanResponse.PlanStep(
                        "tcp_ports", "ports", "requested", Map.of("ports", "8080, 80")))));
    when(toolRegistry.require("tcp_ports")).thenReturn(mock(SecurityTool.class));
    SecurityTask task = new SecurityTask();
    task.setId(42L);
    when(taskService.create(any(CreateTaskRequest.class)))
        .thenAnswer(
            invocation -> {
              CreateTaskRequest create = invocation.getArgument(0);
              assertEquals("80,8080", create.parameters().get("ports"));
              return task;
            });

    AiDispatchResponse response = service.dispatch(request);

    assertEquals(1, response.taskCount());
    assertEquals(List.of(42L), response.taskIds());
    assertFalse(response.plan().requiresConfirmation());
    verify(taskService).create(any(CreateTaskRequest.class));
  }

  @Test
  void rejectsPortsOutsideTargetAuthorizationBeforeCreatingTasks() throws JsonProcessingException {
    AiPlanRequest request = new AiPlanRequest(7L, "scan port 22");
    when(planningService.plan(request))
        .thenReturn(
            new AiPlanResponse(
                "test",
                "test-model",
                "unsafe plan",
                true,
                List.of(
                    new AiPlanResponse.PlanStep(
                        "tcp_ports", "ports", "requested", Map.of("ports", "22")))));
    when(toolRegistry.require("tcp_ports")).thenReturn(mock(SecurityTool.class));

    assertThrows(ApiException.class, () -> service.dispatch(request));
    verify(taskService, never()).create(any(CreateTaskRequest.class));
  }

  @Test
  void rejectsToolsOutsideHardCodedAiWhitelist() throws JsonProcessingException {
    AiPlanRequest request = new AiPlanRequest(7L, "run a command");
    when(planningService.plan(request))
        .thenReturn(
            new AiPlanResponse(
                "test",
                "test-model",
                "unsafe plan",
                true,
                List.of(
                    new AiPlanResponse.PlanStep(
                        "shell", "shell", "not allowed", Map.of("command", "whoami")))));

    assertThrows(ApiException.class, () -> service.dispatch(request));
    verify(toolRegistry, never()).require(any());
    verify(taskService, never()).create(any(CreateTaskRequest.class));
  }

  @Test
  void allowsFullAuthorizedRangeForNmapButKeepsItCompact() throws Exception {
    target.setAllowedPorts("1-65535");
    AiPlanRequest request = new AiPlanRequest(7L, "full port scan");
    when(planningService.plan(request))
        .thenReturn(
            new AiPlanResponse(
                "test",
                "test-model",
                "safe plan",
                true,
                List.of(
                    new AiPlanResponse.PlanStep(
                        "nmap_service_scan",
                        "nmap",
                        "requested",
                        Map.of("ports", "1-65535", "mode", "quick")))));
    when(toolRegistry.require("nmap_service_scan")).thenReturn(mock(SecurityTool.class));
    SecurityTask task = new SecurityTask();
    task.setId(43L);
    when(taskService.create(any(CreateTaskRequest.class)))
        .thenAnswer(
            invocation -> {
              CreateTaskRequest create = invocation.getArgument(0);
              assertEquals("1-65535", create.parameters().get("ports"));
              assertEquals("quick", create.parameters().get("mode"));
              return task;
            });

    AiDispatchResponse response = service.dispatch(request);

    assertEquals(List.of(43L), response.taskIds());
  }

  @Test
  void stillRejectsFullRangeForTcpDispatch() throws JsonProcessingException {
    target.setAllowedPorts("1-65535");
    AiPlanRequest request = new AiPlanRequest(7L, "tcp all ports");
    when(planningService.plan(request))
        .thenReturn(
            new AiPlanResponse(
                "test",
                "test-model",
                "unsafe plan",
                true,
                List.of(
                    new AiPlanResponse.PlanStep(
                        "tcp_ports", "tcp", "requested", Map.of("ports", "1-65535")))));
    when(toolRegistry.require("tcp_ports")).thenReturn(mock(SecurityTool.class));

    assertThrows(ApiException.class, () -> service.dispatch(request));
    verify(taskService, never()).create(any(CreateTaskRequest.class));
  }

  @Test
  void dispatchesAnAlreadyGeneratedStreamingPlanWithoutCallingPlannerAgain() throws Exception {
    AiPlanRequest request = new AiPlanRequest(7L, "检查响应头");
    AiPlanResponse generated =
        new AiPlanResponse(
            "ccs",
            "test-model",
            "safe plan",
            true,
            List.of(new AiPlanResponse.PlanStep("http_headers", "headers", "requested", Map.of())));
    when(toolRegistry.require("http_headers")).thenReturn(mock(SecurityTool.class));
    when(targetPolicyService.validatedHttpUri(target))
        .thenReturn(java.net.URI.create("http://127.0.0.1"));
    SecurityTask task = new SecurityTask();
    task.setId(44L);
    when(taskService.create(any(CreateTaskRequest.class))).thenReturn(task);

    AiDispatchResponse response = service.dispatchPlanned(request, generated);

    assertEquals(List.of(44L), response.taskIds());
    verify(planningService, never()).plan(any());
    verify(taskService, times(1)).create(any(CreateTaskRequest.class));
  }

  @Test
  void dispatchesDifferentBuiltInHttpVulnerabilityChecks() throws Exception {
    target.setTargetType("URL");
    target.setTargetValue("http://127.0.0.1");
    AiPlanRequest request = new AiPlanRequest(7L, "检查 Cookie 和 CORS");
    AiPlanResponse generated =
        new AiPlanResponse(
            "test",
            "test-model",
            "safe plan",
            true,
            List.of(
                new AiPlanResponse.PlanStep(
                    "http_security_check", "cookies", "requested", Map.of("check", "cookies")),
                new AiPlanResponse.PlanStep(
                    "http_security_check", "cors", "requested", Map.of("check", "cors"))));
    when(toolRegistry.require("http_security_check")).thenReturn(mock(SecurityTool.class));
    when(targetPolicyService.validatedHttpUri(target))
        .thenReturn(java.net.URI.create("http://127.0.0.1"));
    SecurityTask first = new SecurityTask();
    first.setId(45L);
    SecurityTask second = new SecurityTask();
    second.setId(46L);
    when(taskService.create(any(CreateTaskRequest.class))).thenReturn(first, second);

    AiDispatchResponse response = service.dispatchPlanned(request, generated);

    assertEquals(List.of(45L, 46L), response.taskIds());
    verify(taskService, times(2)).create(any(CreateTaskRequest.class));
  }
}
