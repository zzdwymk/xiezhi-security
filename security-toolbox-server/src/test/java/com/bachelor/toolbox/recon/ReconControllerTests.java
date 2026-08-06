package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.common.GlobalExceptionHandler;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class ReconControllerTests {
  private final ReconService service = mock(ReconService.class);
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc =
        MockMvcBuilders.standaloneSetup(new ReconController(service))
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
  }

  @Test
  void collectsThroughOriginalRouteAndKeepsJsonFields() throws Exception {
    when(service.collect(eq(5L), any(ReconRequest.class))).thenReturn(result(11L, 5L, 7L));

    mockMvc
        .perform(
            post("/api/projects/{projectId}/recon/collect", 5L)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "targetId":7,
                      "includeHttp":true,
                      "includeTls":false,
                      "mode":"PASSIVE"
                    }
                    """))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").value(11))
        .andExpect(jsonPath("$.projectId").value(5))
        .andExpect(jsonPath("$.targetId").value(7))
        .andExpect(jsonPath("$.rootDomain").value("example.com"));

    ArgumentCaptor<ReconRequest> captor = ArgumentCaptor.forClass(ReconRequest.class);
    verify(service).collect(eq(5L), captor.capture());
    assertThat(captor.getValue().targetId()).isEqualTo(7L);
    assertThat(captor.getValue().includeHttp()).isTrue();
    assertThat(captor.getValue().mode()).isEqualTo("PASSIVE");
  }

  @Test
  void rejectsMissingTargetIdWithChineseMessage() throws Exception {
    mockMvc
        .perform(
            post("/api/projects/{projectId}/recon/collect", 5L)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.message").value("目标 ID 不能为空"));

    verify(service, never()).collect(any(), any());
  }

  @Test
  void exposesBothDescendingHistoryQueries() throws Exception {
    when(service.history(5L)).thenReturn(List.of(result(11L, 5L, 7L)));
    when(service.history(5L, 7L)).thenReturn(List.of(result(12L, 5L, 7L)));

    mockMvc
        .perform(get("/api/projects/{projectId}/recon/results", 5L))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].id").value(11));
    mockMvc
        .perform(get("/api/projects/{projectId}/recon/results", 5L).param("targetId", "7"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].id").value(12));

    verify(service).history(5L);
    verify(service).history(5L, 7L);
  }

  @Test
  void exposesOriginalIcpBatchRouteAndStatusConstants() throws Exception {
    ReconService.IcpResult result =
        new ReconService.IcpResult(7L, "example.com", "AVAILABLE", "查询成功", Map.of("record", "示例"));
    when(service.icpBatch(eq(5L), any(ReconService.IcpBatchRequest.class)))
        .thenReturn(List.of(result));

    mockMvc
        .perform(
            post("/api/projects/{projectId}/recon/icp/batch", 5L)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"targetIds\":[7]}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].targetId").value(7))
        .andExpect(jsonPath("$[0].domain").value("example.com"))
        .andExpect(jsonPath("$[0].status").value("AVAILABLE"));

    verify(service)
        .icpBatch(
            eq(5L),
            org.mockito.ArgumentMatchers.argThat(
                request -> request.targetIds().equals(List.of(7L))));
  }

  @Test
  void rejectsNullTargetInIcpBatchWithChineseMessage() throws Exception {
    mockMvc
        .perform(
            post("/api/projects/{projectId}/recon/icp/batch", 5L)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"targetIds\":[null]}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.message").value("目标 ID 不能为空"));

    verify(service, never()).icpBatch(any(), any());
  }

  private ReconResult result(Long id, Long projectId, Long targetId) {
    ReconResult result = new ReconResult();
    result.setId(id);
    result.setProjectId(projectId);
    result.setTargetId(targetId);
    result.setRootDomain("example.com");
    return result;
  }
}
