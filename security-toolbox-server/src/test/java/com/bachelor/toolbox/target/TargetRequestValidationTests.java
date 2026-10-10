package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * 目标登记请求的长度校验回归测试。
 *
 * <p>背景：{@link AuthorizedTarget} 的列长度是固定的（name 100、targetValue 500、
 * authorizationNote 2000）。在加入 {@code @Size} 之前，超长输入会绕过 Bean Validation
 * 直达数据库，触发约束异常并返回 HTTP 500。桌面模糊测试用 101/300 字符名称稳定复现。
 *
 * <p>本测试锁定"超长输入必须在参数校验阶段被拒绝（→ 400），且边界长度仍然通过"。
 */
class TargetRequestValidationTests {
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

  private static TargetRequest request(String name, String value, String note) {
    return new TargetRequest(
        name,
        value,
        "IP",
        note,
        "80",
        true,
        Instant.now(),
        Instant.now().plusSeconds(3600),
        1L);
  }

  private static Set<ConstraintViolation<TargetRequest>> validate(TargetRequest request) {
    return validator.validate(request);
  }

  @Test
  void acceptsNameAtBoundaryLength() {
    String name = "n".repeat(100);
    assertThat(validate(request(name, "192.168.222.128", "授权"))).isEmpty();
  }

  @Test
  void rejectsNameOverBoundaryLength() {
    // 桌面用例 FZT-20（101 字符）与 FZT-21（300 字符）曾触发 HTTP 500。
    for (int length : new int[] {101, 300}) {
      String name = "n".repeat(length);
      Set<ConstraintViolation<TargetRequest>> violations =
          validate(request(name, "192.168.222.128", "授权"));
      assertThat(violations)
          .as("名称长度 %d 必须被参数校验拒绝", length)
          .anyMatch(v -> "name".equals(v.getPropertyPath().toString()));
    }
  }

  @Test
  void rejectsTargetValueOverBoundaryLength() {
    String value = "1".repeat(501);
    assertThat(validate(request("合法名称", value, "授权")))
        .anyMatch(v -> "targetValue".equals(v.getPropertyPath().toString()));
  }

  @Test
  void rejectsAuthorizationNoteOverBoundaryLength() {
    String note = "a".repeat(2001);
    assertThat(validate(request("合法名称", "192.168.222.128", note)))
        .anyMatch(v -> "authorizationNote".equals(v.getPropertyPath().toString()));
  }

  @Test
  void rejectsAllowedPortsOverBoundaryLength() {
    TargetRequest oversized =
        new TargetRequest(
            "合法名称",
            "192.168.222.128",
            "IP",
            "授权",
            "8".repeat(201),
            true,
            null,
            null,
            1L);
    assertThat(validate(oversized))
        .anyMatch(v -> "allowedPorts".equals(v.getPropertyPath().toString()));
  }

  @Test
  void stillRejectsBlankRequiredFields() {
    Set<ConstraintViolation<TargetRequest>> violations = validate(request("  ", "", "授权"));
    assertThat(violations)
        .anyMatch(v -> "name".equals(v.getPropertyPath().toString()))
        .anyMatch(v -> "targetValue".equals(v.getPropertyPath().toString()));
  }
}
