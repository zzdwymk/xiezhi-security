package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.validation.Validation;
import java.util.List;
import org.junit.jupiter.api.Test;

class AiAgentRequestContextTests {
  private AiAgentRequest automatic(String context, String current) {
    return new AiAgentRequest(5L, 8L, "session", context, null, null, List.of(), "standard", "turn",
        null, null, null, null, null, AiAgentRequest.ExecutionIntent.AUTO, current);
  }

  @Test
  void assembledContextHasItsOwnBudgetAndDoesNotGrantExecution() {
    try (var factory = Validation.buildDefaultValidatorFactory()) {
      var request = automatic("previous context\n".repeat(800), "继续");
      assertThat(factory.getValidator().validate(request)).isEmpty();
      assertThat(request.userPrompt()).isEqualTo("继续");
      assertThat(request.executionRequested()).isFalse();
      assertThat(factory.getValidator().validate(automatic("x".repeat(20001), "继续")))
          .anyMatch(error -> error.getPropertyPath().toString().equals("prompt"));
    }
    assertThatThrownBy(() -> automatic("context", "x".repeat(4001))).isInstanceOf(IllegalArgumentException.class);
  }
}
