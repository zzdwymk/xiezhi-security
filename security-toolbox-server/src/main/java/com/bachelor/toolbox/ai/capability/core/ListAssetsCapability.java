package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.asset.DiscoveredPath;
import com.bachelor.toolbox.asset.DiscoveredPathService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code list_assets} —— 列出已发现的目标资产（子路径）（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code GET /api/targets/{targetId}/discovered-paths}（{@link DiscoveredPathService#listByTarget}）。
 *
 * <h2>目标绑定：为什么这一条是 {@link BindingMode#RESOLVED}</h2>
 *
 * <p>它与 {@code list_findings} 看似同类（都是"列记录"），但语义不同，必须区别对待：
 *
 * <ul>
 *   <li>{@code list_findings} 按<strong>项目/全局</strong>维度检索，不针对某个目标；
 *   <li>本能力<strong>以 targetId 为主键</strong>枚举该目标被发现的全部路径——这等于把"这个目标上有什么"完整摊开，
 *       是后续主动检测的输入。路径枚举结果直接决定后续扫描打哪里。
 * </ul>
 *
 * <p>更重要的是<strong>接口一致性</strong>：{@code /api/targets/{targetId}/discovered-paths} 的路径参数就是
 * {@code targetId}，端点派生能力（路线 B）对它判定的就是"触及目标"（{@code EndpointCapability.isTargetBound} 对路径含
 * {@code target} 段的只读端点返回 {@code true}）。如果手工封装版本反而声明"不触及目标"，就会出现
 * "绕开手工能力、走端点能力会被拦，走手工能力反而放行"的<strong>能力层自相矛盾</strong>——同一个端点两套授权判定，
 * 这是比单个漏洞更危险的设计缺陷。
 *
 * <p>因此本能力把 {@code targetId} 列为必填并进入 L-A 校验，与路线 B 的判定保持一致。
 */
@Component
public class ListAssetsCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "list_assets";

  private static final int MAX_RESULTS = 500;

  private final DiscoveredPathService discoveredPaths;

  public ListAssetsCapability(DiscoveredPathService discoveredPaths) {
    super(
        CODE,
        "列出目标资产",
        "列出某个授权目标上已发现的全部子路径资产（URL、路径、方法、来源、状态码、响应大小）。"
            + "参数：targetId（授权目标 ID，必填）、projectId（可选，项目 ID）、"
            + "path（可选，路径关键字过滤）、limit（可选，条数上限）。"
            + "本能力按目标维度枚举资产，是后续主动检测的输入，因此需要对目标做授权校验。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.discoveredPaths = discoveredPaths;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("targetId", integerProperty(1, "授权目标 ID；资产按目标维度枚举，护栏据此做授权校验"));
    properties.put("projectId", integerProperty(1, "可选：项目 ID"));
    properties.put("path", property("string", "可选：路径关键字过滤"));
    properties.put("limit", integerProperty(1, "可选：返回条数上限，默认 100，最大 " + MAX_RESULTS));
    return objectSchema(properties, List.of("targetId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "targetId");
  }

  /** 列出目标资产。 */
  public List<DiscoveredPath> list(Long targetId, Long projectId, String path, Integer limit) {
    int bounded = Math.min(Math.max(limit == null ? 100 : limit, 1), MAX_RESULTS);
    String filter = path == null ? "" : path.trim();
    return discoveredPaths.list(projectId, targetId).stream()
        .filter(
            asset ->
                filter.isEmpty()
                    || String.valueOf(asset.getPath()).toLowerCase(Locale.ROOT)
                        .contains(filter.toLowerCase(Locale.ROOT)))
        .limit(bounded)
        .toList();
  }
}
