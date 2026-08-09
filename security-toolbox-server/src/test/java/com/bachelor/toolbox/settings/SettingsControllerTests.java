package com.bachelor.toolbox.settings;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.common.GlobalExceptionHandler;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class SettingsControllerTests {
  private BusinessDataResetService service;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    service = mock(BusinessDataResetService.class);
    mockMvc =
        MockMvcBuilders.standaloneSetup(new SettingsController(service))
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
  }

  @Test
  void clearsDataWithExplicitConfirmation() throws Exception {
    Instant clearedAt = Instant.parse("2026-08-07T12:00:00Z");
    when(service.clear("CLEAR"))
        .thenReturn(new BusinessDataResetService.ResetResult(clearedAt, 12, true, 2, 5));

    mockMvc
        .perform(
            delete("/api/settings/data")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"confirmation\":\"CLEAR\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.deletedRecords").value(12))
        .andExpect(jsonPath("$.auditLogRetained").value(true))
        .andExpect(jsonPath("$.clearedProjects").value(2))
        .andExpect(jsonPath("$.runtimeDocumentsDeleted").value(5));

    verify(service).clear("CLEAR");
  }

  @Test
  void rejectsBlankConfirmationBeforeCallingService() throws Exception {
    mockMvc
        .perform(
            delete("/api/settings/data")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"confirmation\":\"\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.message").value("请输入 CLEAR 确认清空数据"));
  }
}
