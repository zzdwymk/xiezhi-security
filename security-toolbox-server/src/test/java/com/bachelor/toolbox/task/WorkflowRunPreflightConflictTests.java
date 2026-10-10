package com.bachelor.toolbox.task;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.common.GlobalExceptionHandler;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class WorkflowRunPreflightConflictTests {
  @Test
  void staleSkipSetReturnsActionableConflictAndTheExactCurrentObservation() throws Exception {
    WorkflowRunService service = mock(WorkflowRunService.class);
    String digest = "sha256:" + "a".repeat(64);
    var current = new WorkflowRunDtos.PreflightResponse("workflow-1", 3L, digest,
        List.of(new WorkflowRunDtos.NodeIssue("tls", "tls_config", "TLS检查", "HTTPS不可用")),
        Map.of("headers", List.of("http://192.168.136.132/")));
    when(service.start(any())).thenThrow(new WorkflowPreflightChangedException(current, List.of("headers")));

    MockMvcBuilders.standaloneSetup(new WorkflowRunController(service))
        .setControllerAdvice(new GlobalExceptionHandler()).build()
        .perform(post("/api/workflow-runs").contentType(MediaType.APPLICATION_JSON).content("""
            {"projectId":7,"targetId":9,"workflowId":"workflow-1","workflowRevision":3,
             "approvedNodeIds":[],"skippedNodeIds":["headers","tls"]}
            """))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("WORKFLOW_PREFLIGHT_CHANGED"))
        .andExpect(jsonPath("$.retryable").value(true))
        .andExpect(jsonPath("$.requiresPreflight").value(true))
        .andExpect(jsonPath("$.message").value(
            "请求跳过的节点不在当前预检的不可用列表中，已拒绝创建工作流；请重新预检并确认后重试"))
        .andExpect(jsonPath("$.rejectedSkippedNodeIds[0]").value("headers"))
        .andExpect(jsonPath("$.currentPreflight.workflowDigest").value(digest))
        .andExpect(jsonPath("$.currentPreflight.issues[0].nodeId").value("tls"))
        .andExpect(jsonPath("$.currentPreflight.resolvedTargets.headers[0]").value("http://192.168.136.132/"));
  }
}
