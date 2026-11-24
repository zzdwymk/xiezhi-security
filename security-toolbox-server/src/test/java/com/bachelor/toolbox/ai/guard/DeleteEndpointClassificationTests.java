package com.bachelor.toolbox.ai.guard;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * 第389轮：删除类端点的「分类门禁」。
 *
 * <p>第386/387/388 轮把清空类端点逐条补进能力黑名单，但"补"是人工的：**新加一个 DELETE 端点不会
 * 自动被审视**，可能悄悄绕过"不可逆破坏必须绝对禁止"的立场。
 *
 * <p>本测试枚举 Spring 实际注册的**全部 DELETE 端点**，要求每一个都落在下面两张表之一：
 *
 * <ol>
 *   <li>{@link #ABSOLUTELY_FORBIDDEN}：必须被 {@link CapabilityBlacklist} 以方法级规则禁止；
 *   <li>{@link #APPROVAL_ONLY}：允许只受"需管理员确认"约束，但必须在此**显式登记并写明理由**。
 * </ol>
 *
 * <p>新增/改名的 DELETE 端点若未登记，本测试立即失败——把"人工判断"固化成可执行的分类清单。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:delete-endpoint-classification;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.ai.api-key=",
      "toolbox.ai.enabled=false",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-ca-password=test-mitm-ca-password-1d6ad9b95b76490e",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.scanner-pocs.import-on-startup=false"
    })
@DisplayName("删除类端点分类门禁（第389轮）")
class DeleteEndpointClassificationTests {

  /** 必须被绝对禁止的 DELETE 端点：清空"全部/整体"且不可恢复。 */
  private static final Set<String> ABSOLUTELY_FORBIDDEN =
      Set.of(
          "/api/findings",
          "/api/vulnerabilities/catalog",
          "/api/settings/data",
          "/api/traffic/sessions");

  /** 允许仅受"需管理员确认"约束的 DELETE 端点：单对象、有归属校验，或授权范围变更需人决策。 */
  private static final Map<String, String> APPROVAL_ONLY = approvalOnly();

  private static Map<String, String> approvalOnly() {
    Map<String, String> map = new LinkedHashMap<>();
    map.put("/api/findings/{id}", "单条发现删除，服务层校验项目归属");
    map.put("/api/projects/{projectId}/discovery/results/{id}", "单条探测结果删除，校验项目归属");
    map.put("/api/traffic/sessions/{packetId}", "单条抓包报文删除，逐条清理");
    map.put("/api/traffic/filters/{id}", "抓包过滤规则删除，配置类操作");
    map.put("/api/targets/{id}", "移除授权目标：授权边界变更，必须由人决策");
    map.put("/api/projects/{id}/targets/{targetId}", "从项目移除授权目标：授权边界变更");
    map.put("/api/scan-schedules/{id}", "删除定时计划，项目内资源");
    map.put("/api/workflow-runs/{id}", "清空工作流运行记录，项目内资源");
    map.put("/api/fingerprints/rules/{ruleId}", "删除自定义指纹规则，配置类操作");
    map.put("/api/ai/memories/{docId}", "删除单条 AI 记忆，含项目归属校验");
    map.put("/api/ai/memories", "按 projectId 清空 AI 记忆，含项目归属校验");
    map.put("/api/ai/agent/sessions/{sessionId}", "清空单个 Agent 会话");
    map.put("/api/ai/conversations/{sessionId}", "删除单个会话线程");
    map.put("/api/ai/conversations", "清空会话线程：非管理员仅限可访问项目（Round 233）");
    map.put("/api/ai/guard/approvals", "撤销 AI 能力授权（CapabilityApprovalController.revoke），授权撤销需管理员操作");
    return Map.copyOf(map);
  }

  @Autowired private RequestMappingHandlerMapping handlerMapping;

  @Test
  @DisplayName("每个 DELETE 端点都必须被显式分类（绝对禁止 / 需审批）")
  void everyDeleteEndpointIsClassified() {
    Set<String> deleteEndpoints = deleteEndpoints();
    assertThat(deleteEndpoints)
        .as("未能枚举到 DELETE 端点，说明枚举方式失效（测试本身需要修复）")
        .isNotEmpty();

    Set<String> unclassified = new TreeSet<>(deleteEndpoints);
    unclassified.removeAll(ABSOLUTELY_FORBIDDEN);
    unclassified.removeAll(APPROVAL_ONLY.keySet());

    assertThat(unclassified)
        .as(
            "以下 DELETE 端点既未列入绝对禁止名单，也未在 APPROVAL_ONLY 中登记理由。"
                + "请判断其是否属于'清空全部且不可恢复'：是则加入 CapabilityBlacklist.DEFAULT_METHOD_PATHS"
                + " 与 ABSOLUTELY_FORBIDDEN；否则在 APPROVAL_ONLY 中写明理由")
        .isEmpty();
  }

  @Test
  @DisplayName("被列为绝对禁止的 DELETE 端点必须真的被能力黑名单拦下")
  void absolutelyForbiddenEndpointsAreActuallyBlocked() {
    CapabilityBlacklist blacklist = CapabilityBlacklist.defaults();
    Set<String> deleteEndpoints = deleteEndpoints();
    for (String path : ABSOLUTELY_FORBIDDEN) {
      assertThat(deleteEndpoints)
          .as("登记为绝对禁止的 %s 在应用里并不存在（分类表过期）", path)
          .contains(path);
      assertThat(blacklist.blocksMethodPath("DELETE", path))
          .as("%s 应被能力黑名单绝对禁止", path)
          .isTrue();
    }
  }

  @Test
  @DisplayName("分类表不得包含已不存在的端点（防止清单腐化）")
  void classificationTablesStayInSyncWithRealEndpoints() {
    Set<String> deleteEndpoints = deleteEndpoints();
    Set<String> stale = new TreeSet<>(APPROVAL_ONLY.keySet());
    stale.removeAll(deleteEndpoints);
    assertThat(stale)
        .as("APPROVAL_ONLY 中存在应用已不再注册的 DELETE 端点，请清理清单")
        .isEmpty();
  }

  /** 枚举所有以 DELETE 方法注册的端点路径模板。 */
  private Set<String> deleteEndpoints() {
    Set<String> paths = new LinkedHashSet<>();
    for (Map.Entry<RequestMappingInfo, HandlerMethod> entry :
        handlerMapping.getHandlerMethods().entrySet()) {
      Set<RequestMethod> methods = entry.getKey().getMethodsCondition().getMethods();
      if (methods.contains(RequestMethod.DELETE)) {
        paths.addAll(patternPaths(entry.getKey()));
      }
    }
    return paths;
  }

  private static List<String> patternPaths(RequestMappingInfo info) {
    List<String> result = new ArrayList<>();
    if (info.getPathPatternsCondition() != null) {
      info.getPathPatternsCondition()
          .getPatternValues()
          .forEach(value -> result.add(normalize(value)));
    }
    return result;
  }

  /** Spring 路径模板与黑名单字面量使用同一形式（{@code {id}}），这里只做去尾斜杠归一。 */
  private static String normalize(String path) {
    if (path == null) {
      return "";
    }
    String trimmed = path.trim();
    if (trimmed.length() > 1 && trimmed.endsWith("/")) {
      return trimmed.substring(0, trimmed.length() - 1);
    }
    return trimmed;
  }
}
