package com.bachelor.toolbox.audit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.ai.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

class AiStreamAuditContextTests {
  private final ExecutorService worker = Executors.newSingleThreadExecutor();

  @AfterEach
  void cleanUp() throws InterruptedException {
    AuditRequestContext.clear();
    worker.shutdownNow();
    assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS));
  }

  @ParameterizedTest
  @CsvSource({"agent,false", "agent,true", "suggest,false", "suggest,true"})
  void streamsRetainOriginatingRequestForAuditAfterRequestEnds(String endpoint, boolean fails)
      throws Exception {
    var logs = mock(AuditLogRepository.class);
    var audit = new AuditService(logs);
    var orchestrator = mock(AgentOrchestrator.class);
    var suggestions = mock(AiWorkflowSuggestService.class);
    var workflows = mock(AgentWorkflowSpecService.class);
    var snapshot = new AgentWorkflowSpecService.WorkflowSnapshot(
        "workflow-1", 1L, 1L, "sha256:" + "a".repeat(64), "alice", Instant.now(),
        Map.of("version", 1, "steps", List.of()), List.of());
    when(workflows.freezeSnapshot(1L, null, null, null)).thenReturn(snapshot);
    doCallRealMethod().when(workflows).withSnapshot(eq(snapshot), any(Runnable.class));
    doCallRealMethod().when(workflows)
        .withSnapshot(eq(snapshot), org.mockito.ArgumentMatchers.<Supplier<AiAgentResponse>>any());
    Runnable auditedWork = () -> {
      audit.record("STREAM", "PROJECT", 1L, endpoint, "SUCCESS");
      if (fails) throw new IllegalStateException("stream failed");
    };
    when(orchestrator.run(any(AiAgentRequest.class), any())).thenAnswer(invocation -> {
      auditedWork.run();
      return null;
    });
    doAnswer(invocation -> {
      auditedWork.run();
      return null;
    }).when(suggestions).stream(any(), any());
    var controller = new AiController(
        null, null, orchestrator, null, workflows, suggestions, new ObjectMapper(), null, null);
    var request = new MockHttpServletRequest();
    request.setRemoteAddr("192.0.2.20");
    var response = new MockHttpServletResponse();
    var body = new AtomicReference<StreamingResponseBody>();

    new AuditRequestContextFilter().doFilter(request, response, (req, res) -> {
      if (endpoint.equals("agent")) {
        body.set(controller.agentStream(new AiAgentRequest(
            1L, 12L, "session", "检查目标", false, null, List.of(), "agent", "turn")).getBody());
      } else {
        body.set(controller.suggestWorkflow(Map.of()).getBody());
      }
    });
    assertNull(AuditRequestContext.get());
    worker.submit(() -> {
      body.get().writeTo(new ByteArrayOutputStream());
      return null;
    }).get(5, TimeUnit.SECONDS);

    var captured = ArgumentCaptor.forClass(AuditLog.class);
    verify(logs).save(captured.capture());
    assertEquals(response.getHeader(AuditRequestContextFilter.REQUEST_ID_HEADER), captured.getValue().getRequestId());
    assertEquals("192.0.2.20", captured.getValue().getSourceIp());
    assertNull(worker.submit(AuditRequestContext::get).get(5, TimeUnit.SECONDS));
  }
}
