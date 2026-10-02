package com.bachelor.toolbox.ai;

final class AiUserFacingLanguage {
  private AiUserFacingLanguage() {}

  static final String PROMPT = """
      面向用户的说明、摘要、标题、原因和建议均使用自然中文。状态在正文中按语义说明：
      ACTIVE 表示授权有效，SUCCESS 表示执行成功，FAILED 表示执行失败，TIMEOUT 表示超时；
      PENDING 根据上下文表述为等待处理或等待审批。不要写“处于ACTIVE状态”等直接拼接状态代码的句子。
      此要求只适用于面向用户的自然语言；JSON 字段名、协议枚举值、工具代码和 ID 必须保持原样，
      不得翻译或全局替换。引用具体工具代码、节点 ID 或证据 ID 时也保留原值。
      """;
}
