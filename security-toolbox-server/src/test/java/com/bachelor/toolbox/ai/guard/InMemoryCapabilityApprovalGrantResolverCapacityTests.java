package com.bachelor.toolbox.ai.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Round 232：按需授权凭据必须有容量上限，避免长期运行无界增长。 */
class InMemoryCapabilityApprovalGrantResolverCapacityTests {

  @Test
  void activeGrantsAreBoundedAndOverflowFailsClosed() {
    InMemoryCapabilityApprovalGrantResolver resolver =
        new InMemoryCapabilityApprovalGrantResolver();

    for (int i = 0; i < InMemoryCapabilityApprovalGrantResolver.MAX_GRANTS; i++) {
      resolver.grant(request(i), ApprovalLevel.SESSION);
    }
    assertThat(resolver.size()).isEqualTo(InMemoryCapabilityApprovalGrantResolver.MAX_GRANTS);

    assertThatThrownBy(
            () -> resolver.grant(request(InMemoryCapabilityApprovalGrantResolver.MAX_GRANTS), ApprovalLevel.SESSION))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("上限");
    assertThat(resolver.size()).isEqualTo(InMemoryCapabilityApprovalGrantResolver.MAX_GRANTS);
  }

  @Test
  void oneTimeGrantIsConsumed() {
    InMemoryCapabilityApprovalGrantResolver resolver =
        new InMemoryCapabilityApprovalGrantResolver();
    CapabilityApprovalRequest request = request(1);

    resolver.grant(request, ApprovalLevel.SINGLE);
    assertThat(resolver.hasValidApproval("cap-1", "target-1", "digest-1")).isTrue();
    assertThat(resolver.hasValidApproval("cap-1", "target-1", "digest-1")).isFalse();
    assertThat(resolver.size()).isZero();
  }

  private static CapabilityApprovalRequest request(int index) {
    return new CapabilityApprovalRequest(
        "cap-" + index,
        "target-1",
        "digest-" + index,
        "LOW",
        ApprovalLevel.SESSION,
        "测试申请",
        Map.of());
  }
}
