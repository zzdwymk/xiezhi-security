package com.bachelor.toolbox.probe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.GlobalExceptionHandler;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class ProbeControllerTests {
  private final ProbeService service = mock(ProbeService.class);
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc =
        MockMvcBuilders.standaloneSetup(new ProbeController(service))
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
  }

  @Test
  void probesThroughOriginalRouteAndUsesProjectIdFromPath() throws Exception {
    ProbeResult result = result(11L, 5L, 7L);
    when(service.probe(any(ProbeRequest.class))).thenReturn(result);

    mockMvc
        .perform(
            post("/api/projects/{projectId}/discovery/probe", 5L)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"projectId":99,"targetId":7,"url":"https://example.com"}
                    """))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").value(11))
        .andExpect(jsonPath("$.projectId").value(5))
        .andExpect(jsonPath("$.targetId").value(7));

    ArgumentCaptor<ProbeRequest> captor = ArgumentCaptor.forClass(ProbeRequest.class);
    verify(service).probe(captor.capture());
    assertThat(captor.getValue().getProjectId()).isEqualTo(5L);
    assertThat(captor.getValue().getUrl()).isEqualTo("https://example.com");
  }

  @Test
  void rejectsMissingTargetIdWithChineseMessage() throws Exception {
    mockMvc
        .perform(
            post("/api/projects/{projectId}/discovery/probe", 5L)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.message").value("目标 ID 不能为空"));

    verify(service, never()).probe(any());
  }

  @Test
  void returnsBadRequestWhenProjectAuthorizationIsInactive() throws Exception {
    when(service.probe(any(ProbeRequest.class)))
        .thenThrow(new ApiException("项目授权已过期或尚未生效"));

    mockMvc
        .perform(
            post("/api/projects/{projectId}/discovery/probe", 5L)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"targetId\":7}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.message").value("项目授权已过期或尚未生效"));
  }

  @Test
  void exposesBothDescendingHistoryQueries() throws Exception {
    when(service.history(5L)).thenReturn(List.of(result(11L, 5L, 7L)));
    when(service.history(5L, 7L)).thenReturn(List.of(result(12L, 5L, 7L)));

    mockMvc
        .perform(get("/api/projects/{projectId}/discovery/results", 5L))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].id").value(11));
    mockMvc
        .perform(get("/api/projects/{projectId}/discovery/results", 5L).param("targetId", "7"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].id").value(12));

    verify(service).history(5L);
    verify(service).history(5L, 7L);
  }

  private ProbeResult result(Long id, Long projectId, Long targetId) {
    ProbeResult result = new ProbeResult();
    result.setId(id);
    result.setProjectId(projectId);
    result.setTargetId(targetId);
    result.setUrl("https://example.com");
    return result;
  }
}
