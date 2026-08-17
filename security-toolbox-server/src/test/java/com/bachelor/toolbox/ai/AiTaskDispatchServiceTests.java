package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AiTaskDispatchServiceTests {
  private final TargetService targetService = mock(TargetService.class);
  private final TargetPolicyService targetPolicyService = mock(TargetPolicyService.class);
  private final SecurityToolRegistry toolRegistry = mock(SecurityToolRegistry.class);
  private final PortRangeParser portRangeParser = new PortRangeParser();
  private AiTaskDispatchService service;
  private AuthorizedTarget target;

  @BeforeEach
  void setUp() {
    service =
        new AiTaskDispatchService(
            targetService,
            targetPolicyService,
            toolRegistry,
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
    AiPlanResponse generated =
        new AiPlanResponse("test", "test-model", "你好！", false, List.of());

    AiPlanResponse response = service.prepare(request, generated);

    assertEquals(List.of(), response.steps());
  }

  @Test
  void dispatchesValidatedPlanAndCanonicalizesAuthorizedPorts() throws Exception {
    AiPlanRequest request = new AiPlanRequest(7L, "scan selected ports");
    AiPlanResponse generated =
        new AiPlanResponse(
                "test",
                "test-model",
                "safe plan",
                true,
                List.of(
                    new AiPlanResponse.PlanStep(
                        "tcp_ports", "ports", "requested", Map.of("ports", "8080, 80"))));
    when(toolRegistry.require("tcp_ports")).thenReturn(mock(SecurityTool.class));

    AiPlanResponse response = service.prepare(request, generated);

    assertEquals("80,8080", response.steps().get(0).parameters().get("ports"));
    assertFalse(response.requiresConfirmation());
  }

  @Test
  void rejectsPortsOutsideTargetAuthorizationBeforeCreatingTasks() {
    AiPlanRequest request = new AiPlanRequest(7L, "scan port 22");
    AiPlanResponse generated =
        new AiPlanResponse(
                "test",
                "test-model",
                "unsafe plan",
                true,
                List.of(
                    new AiPlanResponse.PlanStep(
                        "tcp_ports", "ports", "requested", Map.of("ports", "22"))));
    when(toolRegistry.require("tcp_ports")).thenReturn(mock(SecurityTool.class));

    assertThrows(ApiException.class, () -> service.prepare(request, generated));
  }

  @Test
  void rejectsToolsOutsideHardCodedAiWhitelist() {
    AiPlanRequest request = new AiPlanRequest(7L, "run a command");
    AiPlanResponse generated =
        new AiPlanResponse(
                "test",
                "test-model",
                "unsafe plan",
                true,
                List.of(
                    new AiPlanResponse.PlanStep(
                        "shell", "shell", "not allowed", Map.of("command", "whoami"))));

    assertThrows(ApiException.class, () -> service.prepare(request, generated));
    verify(toolRegistry, never()).require(any());
  }

  @Test
  void allowsFullAuthorizedRangeForNmapButKeepsItCompact() throws Exception {
    target.setAllowedPorts("1-65535");
    AiPlanRequest request = new AiPlanRequest(7L, "full port scan");
    AiPlanResponse generated =
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
                        Map.of("ports", "1-65535", "mode", "quick"))));
    when(toolRegistry.require("nmap_service_scan")).thenReturn(mock(SecurityTool.class));

    AiPlanResponse response = service.prepare(request, generated);

    assertEquals("1-65535", response.steps().get(0).parameters().get("ports"));
    assertEquals("quick", response.steps().get(0).parameters().get("mode"));
  }

  @Test
  void stillRejectsFullRangeForTcpDispatch() {
    target.setAllowedPorts("1-65535");
    AiPlanRequest request = new AiPlanRequest(7L, "tcp all ports");
    AiPlanResponse generated =
        new AiPlanResponse(
                "test",
                "test-model",
                "unsafe plan",
                true,
                List.of(
                    new AiPlanResponse.PlanStep(
                        "tcp_ports", "tcp", "requested", Map.of("ports", "1-65535"))));
    when(toolRegistry.require("tcp_ports")).thenReturn(mock(SecurityTool.class));

    assertThrows(ApiException.class, () -> service.prepare(request, generated));
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
    AiPlanResponse response = service.prepare(request, generated);

    assertEquals("http_headers", response.steps().get(0).toolCode());
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
    AiPlanResponse response = service.prepare(request, generated);

    assertEquals(2, response.steps().size());
  }

  @Test
  void preservesDistinctScannerCodesAndPocSelectionContracts() throws Exception {
    target.setTargetType("URL");
    target.setTargetValue("https://127.0.0.1");
    when(targetPolicyService.validatedHttpUri(target))
        .thenReturn(java.net.URI.create("https://127.0.0.1"));
    for (String tool : List.of("nuclei_scan", "afrog_scan", "xray_scan")) {
      when(toolRegistry.require(tool)).thenReturn(mock(SecurityTool.class));
    }
    AiPlanResponse generated =
        new AiPlanResponse(
            "test",
            "test-model",
            "scanner plan",
            true,
            List.of(
                new AiPlanResponse.PlanStep(
                    "nuclei_scan", "Nuclei", "requested", Map.of()),
                new AiPlanResponse.PlanStep(
                    "afrog_scan", "Afrog", "requested", Map.of("allPocs", true)),
                new AiPlanResponse.PlanStep(
                    "xray_scan",
                    "Xray",
                    "requested",
                    Map.of("pocCodes", List.of("XR-AAAAAAAAAAAAAAAAAAAAAAAA")))));

    AiPlanResponse response = service.prepare(new AiPlanRequest(7L, "run scanners"), generated);

    assertEquals(
        List.of("nuclei_scan", "afrog_scan", "xray_scan"),
        response.steps().stream().map(AiPlanResponse.PlanStep::toolCode).toList());
    assertEquals(Map.of("allPocs", true), response.steps().get(1).parameters());
    assertEquals(
        Map.of("pocCodes", List.of("XR-AAAAAAAAAAAAAAAAAAAAAAAA")),
        response.steps().get(2).parameters());
  }

  @Test
  void rejectsAfrogWithoutAnExplicitPocSelection() {
    when(toolRegistry.require("afrog_scan")).thenReturn(mock(SecurityTool.class));
    AiPlanResponse generated =
        new AiPlanResponse(
            "test",
            "test-model",
            "invalid scanner plan",
            true,
            List.of(
                new AiPlanResponse.PlanStep(
                    "afrog_scan", "Afrog", "requested", Map.of())));

    assertThrows(
        ApiException.class,
        () -> service.prepare(new AiPlanRequest(7L, "run afrog"), generated));
  }
}
