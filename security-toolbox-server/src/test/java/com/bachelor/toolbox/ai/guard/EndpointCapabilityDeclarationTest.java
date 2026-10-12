package com.bachelor.toolbox.ai.guard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointCapability;
import com.bachelor.toolbox.ai.endpoint.RiskInference;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 验证 P1-3 修复：{@link EndpointCapability} 显式声明三态，使只读端点能力的空集被护栏认可。
 *
 * <p>本测试固化"合法通过护栏"的判定链，并断言声明与行为一致（防止 fail-open）。
 */
class EndpointCapabilityDeclarationTest {

  /** 覆盖各类端点形态：只读无目标段、只读含目标段、写方法、各 HTTP 动词。 */
  private static List<EndpointCapability> samples() {
    List<EndpointCapability> list = new ArrayList<>();
    String[][] cases = {
      // 只读、路径无 target 段 → 期望 targetBound=false（空集合法）
      {"GET", "/api/vulnerabilities"},
      {"GET", "/api/tools"},
      {"GET", "/api/audits"},
      {"HEAD", "/api/health"},
      {"OPTIONS", "/api/cors"},
      // 只读、路径含 target 段 → 期望 targetBound=true（哨兵）
      {"GET", "/api/targets"},
      {"GET", "/api/targets/{targetId}"},
      {"GET", "/api/projects/{projectId}/targets/{targetId}/paths"},
      // 写方法 → 一律 targetBound=true
      {"POST", "/api/tasks"},
      {"POST", "/api/tasks/{id}/retry"},
      {"PUT", "/api/projects/{projectId}"},
      {"PATCH", "/api/findings/{id}"},
      {"DELETE", "/api/targets/{targetId}"},
    };
    for (String[] c : cases) {
      String method = c[0];
      String path = c[1];
      list.add(
          new EndpointCapability(
              method,
              path,
              RiskInference.inferKind(method, path),
              RiskInference.inferRisk(method, path),
              RiskInference.inferRequiresApproval(method, path),
              EndpointCapability.isTargetBound(method, path),
              "测试端点"));
    }
    return list;
  }

  // ==================================================================
  // 1. 声明存在且被护栏识别（修复的核心）
  // ==================================================================

  @Test
  @DisplayName("P1-3-1 只读端点：显式声明 NONE，护栏认可空集合法")
  void readOnlyEndpointsDeclareNoneSoEmptySetIsLegal() {
    for (EndpointCapability capability : samples()) {
      if (capability.isTargetBound()) {
        continue;
      }
      assertEquals(
          TargetBindingProbe.Declaration.NONE,
          TargetBindingProbe.declarationOf(capability),
          capability.code() + " 只读端点必须声明 NONE");
      assertTrue(
          TargetBindingProbe.emptyBindingAllowed(capability),
          capability.code() + " 只读端点的空集必须被护栏认可（否则能力归零）");
      assertTrue(
          capability.targetBindings(Map.of()).isEmpty(),
          capability.code() + " 只读端点必须返回空集");
    }
  }

  @Test
  @DisplayName("P1-3-2 触及目标的端点：声明 REQUIRED，空集不合法（fail-closed）")
  void targetBoundEndpointsDeclareRequired() {
    for (EndpointCapability capability : samples()) {
      if (!capability.isTargetBound()) {
        continue;
      }
      assertEquals(
          TargetBindingProbe.Declaration.REQUIRED,
          TargetBindingProbe.declarationOf(capability),
          capability.code() + " 触及目标的端点必须声明 REQUIRED");
      assertFalse(
          TargetBindingProbe.emptyBindingAllowed(capability),
          capability.code() + " 触及目标的端点不得让空集合法");
    }
  }

  // ==================================================================
  // 2. 一致性断言：声明与实际行为必须一致（防止 fail-open）
  // ==================================================================

  @Test
  @DisplayName("P1-3-3 声明与 targetBindings 行为严格一致（防 fail-open）")
  void declarationMustMatchActualBindingBehavior() {
    for (EndpointCapability capability : samples()) {
      boolean declared = capability.targetBindingsDeclared();
      var actual = capability.targetBindings(Map.of());

      if (declared) {
        assertFalse(
            actual.isEmpty(),
            capability.code()
                + " 声明触及目标，却在空参数下返回空集 → 护栏会跳过 L-A（fail-open）");
      } else {
        assertTrue(
            actual.isEmpty(),
            capability.code() + " 声明不触及目标，却返回非空 → 语义不符");
      }
    }
  }

  // ==================================================================
  // 3. 安全性：写方法一律 targetBound=true（补丁不放开写操作）
  // ==================================================================

  @Test
  @DisplayName("P1-3-4 所有非读方法一律 targetBound=true（补丁不放开任何写操作）")
  void everyWriteMethodIsTargetBound() {
    for (String method : List.of("POST", "PUT", "PATCH", "DELETE")) {
      for (String path : List.of("/api/vulnerabilities", "/api/tools", "/api/audits")) {
        assertTrue(
            EndpointCapability.isTargetBound(method, path),
            method + " " + path + " 是写方法，必须 targetBound=true（绝不可跳过 L-A）");
        assertFalse(
            EndpointCapability.isTargetBound(method, path)
                && TargetBindingProbe.emptyBindingAllowed(
                    new EndpointCapability(
                        method,
                        path,
                        RiskInference.inferKind(method, path),
                        RiskInference.inferRisk(method, path),
                        RiskInference.inferRequiresApproval(method, path),
                        EndpointCapability.isTargetBound(method, path),
                        "测试")),
            method + " " + path + " 写方法的空集绝不可合法");
      }
    }
  }

  @Test
  @DisplayName("P1-3-5 路径含 target 段的只读端点仍视为触及目标")
  void readOnlyWithTargetSegmentIsStillBound() {
    for (String path :
        List.of(
            "/api/targets",
            "/api/targets/{targetId}",
            "/api/projects/{projectId}/targets",
            "/api/target-assets",
            "/api/target_groups")) {
      assertTrue(
          EndpointCapability.isTargetBound("GET", path),
          "GET " + path + " 含 target 段，必须 targetBound=true");
    }
  }

  // ==================================================================
  // 4. 回归：既有能力（SecurityTool / 核心能力）的声明未受影响
  // ==================================================================

  @Test
  @DisplayName("P1-3-6 哨兵端点：声明 REQUIRED，绝不返回空集")
  void sentinelEndpointsReturnSentinelAndDeclareRequired() {
    for (EndpointCapability capability : samples()) {
      if (!capability.isTargetBound()) {
        continue;
      }
      var bindings = capability.targetBindings(Map.of());
      assertEquals(1, bindings.size(), capability.code() + " 应返回单个哨兵");
      assertTrue(
          bindings.contains(AgentCapability.TARGET_BINDING_UNRESOLVED),
          capability.code() + " 应返回哨兵而不是空集（空集=宣称不触及目标=fail-open）");
    }
  }
}
