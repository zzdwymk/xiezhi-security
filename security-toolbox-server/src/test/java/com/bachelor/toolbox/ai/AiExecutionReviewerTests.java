package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AiExecutionReviewerTests {
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final AiExecutionReviewer reviewer = new AiExecutionReviewer(tasks);

  @ParameterizedTest
  @ValueSource(strings = {"PENDING", "RUNNING", "UNKNOWN"})
  void unfinishedTasksDoNotClaimCompletedReviewOrRetryDecision(String status) {
    task(1L, status);
    var review = reviewer.review(5L, 8L, List.of(1L));
    assertThat(review.status()).isEqualTo("PENDING");
    assertThat(review.retryAllowed()).isFalse();
    assertThat(review.summary()).contains("尚未结束", "不包含检测证据");
  }

  @ParameterizedTest
  @ValueSource(strings = {"SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED"})
  void terminalStatusDeterminesRetryWithoutClaimingEvidenceVerification(String status) {
    task(1L, status);
    var review = reviewer.review(5L, 8L, List.of(1L));
    assertThat(review.status()).isEqualTo("ACCEPTED");
    assertThat(review.retryAllowed()).isEqualTo(!"SUCCESS".equals(status));
    assertThat(review.summary()).contains("状态已终结", "不包含检测证据");
  }

  @Test
  void mixedTasksPreserveBothPendingAndFailedRetryEligibility() {
    task(1L, "RUNNING");
    task(2L, "FAILED");
    var review = reviewer.review(5L, 8L, List.of(1L, 2L));
    assertThat(review.status()).isEqualTo("PENDING");
    assertThat(review.retryAllowed()).isTrue();
  }

  @Test
  void absentTasksAndWrongOwnershipNeverClaimReviewSuccess() {
    assertThat(reviewer.review(5L, 8L, List.of()).status()).isEqualTo("NO_ACTION");
    verifyNoInteractions(tasks);
    task(1L, "SUCCESS");
    assertThat(reviewer.review(6L, 8L, List.of(1L)).status()).isEqualTo("REJECTED");
  }

  private void task(long id, String status) {
    SecurityTask task = new SecurityTask();
    task.setId(id);
    task.setProjectId(5L);
    task.setTargetId(8L);
    task.setStatus(status);
    when(tasks.findById(id)).thenReturn(Optional.of(task));
  }
}
