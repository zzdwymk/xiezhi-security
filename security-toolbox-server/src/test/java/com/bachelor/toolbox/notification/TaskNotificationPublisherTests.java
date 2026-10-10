package com.bachelor.toolbox.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.task.SecurityTask;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TaskNotificationPublisherTests {
  private final NotificationService notifications = mock(NotificationService.class);
  private final TaskNotificationPublisher publisher = new TaskNotificationPublisher(notifications, new ObjectMapper());

  @ParameterizedTest @ValueSource(strings = {"SUCCESS", "FAILED", "TIMEOUT", "REJECTED"})
  void terminalResultsIncludeSavedSeverityAndStableIdentity(String status) {
    SecurityTask task = task(status);
    task.setResultJson("{\"findings\":[{\"severity\":\"high\"},{\"severity\":\"HIGH\"}]}");
    when(notifications.findingSeverities(List.of(8L))).thenReturn(List.of("HIGH"));
    publisher.publish(task);
    verify(notifications).publish(eq("task:8:" + status), eq(5L), eq(false), eq("task"),
        eq("SUCCESS".equals(status) ? "success" : "error"), anyString(), anyString(),
        eq("/tasks?taskId=8"), eq(List.of("HIGH")));
  }

  @ParameterizedTest @ValueSource(strings = {"CANCELLED", "SKIPPED", "PENDING", "RUNNING"})
  void quietStatesDoNotNotify(String status) {
    publisher.publish(task(status));
    verifyNoInteractions(notifications);
  }

  @Test void workflowChildrenUseOnlyWorkflowSummary() {
    SecurityTask task = task("SUCCESS");
    task.setWorkflowRunId(42L);
    publisher.publish(task);
    verifyNoInteractions(notifications);
  }

  @Test void failedTaskUsesPersistedPartialFindingsWhenResultJsonIsMissing() {
    SecurityTask task = task("FAILED");
    when(notifications.findingSeverities(List.of(8L))).thenReturn(List.of("HIGH"));
    publisher.publish(task);
    verify(notifications).publish(eq("task:8:FAILED"), eq(5L), eq(false), eq("task"), eq("error"),
        anyString(), anyString(), eq("/tasks?taskId=8"), eq(List.of("HIGH")));
  }

  @Test void rawResultCannotPromoteAnUnsavedCriticalFinding() {
    SecurityTask task = task("TIMEOUT");
    task.setResultJson("{\"findings\":[{\"severity\":\"CRITICAL\"}]}");
    when(notifications.findingSeverities(List.of(8L))).thenReturn(List.of("LOW"));
    publisher.publish(task);
    verify(notifications).publish(eq("task:8:TIMEOUT"), eq(5L), eq(false), eq("task"), eq("error"),
        anyString(), anyString(), eq("/tasks?taskId=8"), eq(List.of("LOW")));
  }

  @Test void missingOrMalformedResultsDoNotInventSeverity() {
    assertThat(NotificationService.resultSeverities(new ObjectMapper(), null)).isEmpty();
    assertThat(NotificationService.resultSeverities(new ObjectMapper(), "not-json")).isEmpty();
  }

  private SecurityTask task(String status) {
    SecurityTask task = new SecurityTask();
    task.setId(8L);
    task.setProjectId(5L);
    task.setToolCode("nuclei_scan");
    task.setStatus(status);
    return task;
  }
}
