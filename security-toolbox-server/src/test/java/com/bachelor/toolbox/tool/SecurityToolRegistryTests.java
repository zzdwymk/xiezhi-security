package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import org.junit.jupiter.api.Test;

class SecurityToolRegistryTests {
  @Test
  void duplicateCodesFailAtConstructionInsteadOfReplacingTheExecutor() {
    assertThatThrownBy(() -> new SecurityToolRegistry(List.of(tool("same"), tool("same"))))
        .isInstanceOf(IllegalStateException.class).hasMessageContaining("重复注册: same");
  }

  @Test
  void missingCodeFailsAtConstruction() {
    for (String code : new String[] {null, "", " "}) {
      assertThatThrownBy(() -> new SecurityToolRegistry(List.of(tool(code))))
          .isInstanceOf(IllegalStateException.class).hasMessageContaining("code 不能为空");
    }
  }

  @Test
  void distinctToolsKeepTheirExecutorAndRegistrationOrder() {
    SecurityTool first = tool("first");
    SecurityTool second = tool("second");
    var registry = new SecurityToolRegistry(List.of(first, second));
    assertThat(registry.all()).containsExactly(first, second);
    assertThat(registry.require("first")).isSameAs(first);
    assertThat(registry.require("second")).isSameAs(second);
  }

  private static SecurityTool tool(String code) {
    SecurityTool tool = mock(SecurityTool.class);
    when(tool.code()).thenReturn(code);
    return tool;
  }
}
