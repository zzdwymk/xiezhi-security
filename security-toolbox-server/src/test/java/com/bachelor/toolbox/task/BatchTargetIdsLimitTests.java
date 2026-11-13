package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 批量下发 targetIds 数量上限校验——Round 31。
 *
 * <p>背景：{@code AiAgentRequest}/{@code ProjectBatchTaskRequest} 的 {@code targetIds} 原无大小上限，
 * 超长列表会在授权校验阶段对其逐目标做 DB 归属校验，形成无界扇出（慢查询 DoS）。本测试锁定
 * "超过 200 必须在参数校验阶段被拒绝，边界 200 仍然通过"。
 */
@DisplayName("批量目标数量上限校验（Round 31）")
class BatchTargetIdsLimitTests {
  private static ValidatorFactory factory;
  private static Validator validator;

  @BeforeAll
  static void setUp() {
    factory = Validation.buildDefaultValidatorFactory();
    validator = factory.getValidator();
  }

  @AfterAll
  static void tearDown() {
    if (factory != null) factory.close();
  }

  private static List<Long> ids(int n) {
    List<Long> list = new ArrayList<>();
    for (int i = 1; i <= n; i++) list.add((long) i);
    return list;
  }

  private static Set<ConstraintViolation<ProjectBatchTaskRequest>> validateBatch(List<Long> targetIds) {
    return validator.validate(new ProjectBatchTaskRequest(1L, "tcp_ports", Map.of(), targetIds));
  }

  @Test
  @DisplayName("BT-1 targetIds 超过 200 → 校验失败")
  void rejectsTooManyTargetIds() {
    assertThat(validateBatch(ids(201))).isNotEmpty();
  }

  @Test
  @DisplayName("BT-2 targetIds 恰为 200 → 通过")
  void allowsExactly200() {
    assertThat(validateBatch(ids(200))).isEmpty();
  }

  @Test
  @DisplayName("BT-3 targetIds 为空（全部目标）→ 通过")
  void allowsEmpty() {
    assertThat(validateBatch(null)).isEmpty();
  }
}
