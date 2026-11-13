package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 词条校验请求的数量上限——Round 33。
 *
 * <p>背景：{@code PathDictionaryController.ValidateRequest}/{@code SubdomainDictionaryController.ValidateRequest}
 * 的 {@code words} 原无大小上限，{@code validateWords} 会逐条为非法词条生成问题串并回显，超大列表放大内存。
 * 现加 {@code @Size(max=100000)}（与 import 上限对齐），本测试锁定边界行为。
 */
@DisplayName("词条校验数量上限（Round 33）")
class DictionaryValidateRequestLimitTests {
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

  private static List<String> words(int n) {
    List<String> list = new ArrayList<>();
    for (int i = 0; i < n; i++) list.add("w" + i);
    return list;
  }

  @Test
  @DisplayName("DV-1 Path 校验 100001 词 → 失败")
  void pathRejectsTooMany() {
    Set<ConstraintViolation<PathDictionaryController.ValidateRequest>> v =
        validator.validate(new PathDictionaryController.ValidateRequest(words(100_001)));
    assertThat(v).isNotEmpty();
  }

  @Test
  @DisplayName("DV-2 Path 校验 100000 词 → 通过（边界不误伤）")
  void pathAllowsBoundary() {
    Set<ConstraintViolation<PathDictionaryController.ValidateRequest>> v =
        validator.validate(new PathDictionaryController.ValidateRequest(words(100_000)));
    assertThat(v).isEmpty();
  }

  @Test
  @DisplayName("DV-3 Subdomain 校验 100001 词 → 失败")
  void subdomainRejectsTooMany() {
    Set<ConstraintViolation<SubdomainDictionaryController.ValidateRequest>> v =
        validator.validate(new SubdomainDictionaryController.ValidateRequest(words(100_001)));
    assertThat(v).isNotEmpty();
  }
}
