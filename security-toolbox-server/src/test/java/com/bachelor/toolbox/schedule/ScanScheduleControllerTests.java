package com.bachelor.toolbox.schedule;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class ScanScheduleControllerTests {
  private final ScanScheduleService service = mock(ScanScheduleService.class);
  private final ObjectMapper objectMapper = new ObjectMapper();
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.standaloneSetup(new ScanScheduleController(service)).build();
  }

  @Test
  void exposesListAndDetailRoutes() throws Exception {
    ScanSchedule schedule = schedule(11L);
    when(service.list()).thenReturn(List.of(schedule));
    when(service.get(11L)).thenReturn(schedule);

    mockMvc
        .perform(get("/api/scan-schedules"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].id").value(11));
    mockMvc
        .perform(get("/api/scan-schedules/{id}", 11L))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.toolCode").value("http_headers"));
  }

  @Test
  void createsScheduleWithOriginalStatusAndJsonFields() throws Exception {
    ScanSchedule schedule = schedule(11L);
    when(service.create(any(CreateScheduleRequest.class))).thenReturn(schedule);
    String body =
        objectMapper.writeValueAsString(
            new CreateScheduleRequest(
                5L, 7L, "http_headers", java.util.Map.of("depth", 2), null, 3600L, true));

    mockMvc
        .perform(post("/api/scan-schedules").contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.id").value(11))
        .andExpect(jsonPath("$.projectId").value(5))
        .andExpect(jsonPath("$.targetId").value(7))
        .andExpect(jsonPath("$.toolCode").value("http_headers"))
        .andExpect(jsonPath("$.intervalSeconds").value(3600))
        .andExpect(jsonPath("$.enabled").value(true));

    ArgumentCaptor<CreateScheduleRequest> requestCaptor =
        ArgumentCaptor.forClass(CreateScheduleRequest.class);
    verify(service).create(requestCaptor.capture());
    assertEquals(2, requestCaptor.getValue().parameters().get("depth"));
  }

  @Test
  void rejectsInvalidCreateRequestBeforeCallingService() throws Exception {
    mockMvc
        .perform(post("/api/scan-schedules").contentType(MediaType.APPLICATION_JSON).content("{}"))
        .andExpect(status().isBadRequest());

    verify(service, never()).create(any());
  }

  @Test
  void exposesEnableAndDisableRoutes() throws Exception {
    when(service.toggle(11L, true)).thenReturn(schedule(11L));
    when(service.toggle(11L, false)).thenReturn(schedule(11L));

    mockMvc.perform(post("/api/scan-schedules/{id}/enable", 11L)).andExpect(status().isOk());
    mockMvc.perform(post("/api/scan-schedules/{id}/disable", 11L)).andExpect(status().isOk());

    verify(service).toggle(11L, true);
    verify(service).toggle(11L, false);
  }

  @Test
  void deletesScheduleThroughOriginalRoute() throws Exception {
    mockMvc.perform(delete("/api/scan-schedules/{id}", 11L)).andExpect(status().isOk());

    verify(service).delete(11L);
  }

  private ScanSchedule schedule(Long id) {
    ScanSchedule schedule = new ScanSchedule();
    schedule.setId(id);
    schedule.setProjectId(5L);
    schedule.setTargetId(7L);
    schedule.setToolCode("http_headers");
    schedule.setParametersJson("{\"depth\":2}");
    schedule.setIntervalSeconds(3600L);
    schedule.setEnabled(true);
    return schedule;
  }
}
