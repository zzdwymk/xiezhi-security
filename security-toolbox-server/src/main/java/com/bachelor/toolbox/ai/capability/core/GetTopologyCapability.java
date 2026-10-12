package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.fingerprint.FingerprintRuleCatalog;
import com.bachelor.toolbox.fingerprint.SafePocLinkService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code get_topology} —— 查询资产拓扑与指纹统计（设计文档 §4.2 路线 A 的"资产"域）。
 *
 * <p>封装 {@code GET /api/fingerprints/catalog} 与 {@code POST /api/fingerprints/poc-recommendations} 的只读语义
 * （{@link FingerprintRuleCatalog} 的规则目录统计）。
 *
 * <h2>目标绑定：{@link BindingMode#NONE}</h2>
 *
 * <p>本能力返回的是<strong>平台内置的指纹规则目录与统计</strong>（规则总数、分类分布、启用的 PoC 关联），
 * 不是"某个目标上跑了哪些指纹"。它不读取任何目标数据，也不向任何目标发包，因此是合法的真空集。
 *
 * <h2>一个必须写清楚的边界</h2>
 *
 * <p>如果将来要加"查询<strong>某个目标</strong>的指纹拓扑"，那必须是<strong>另一个能力</strong>并声明
 * {@link BindingMode#RESOLVED}——不能把 {@code targetId} 作为可选参数加进本能力然后"有就校验、没有就跳过"。
 * 那种"参数驱动的校验开关"正是 §10 失败模式表里"校验只覆盖部分调用路径（X-7）"的同类问题：新增路径自动继承缺口。
 */
@Component
public class GetTopologyCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "get_topology";

  private final FingerprintRuleCatalog catalog;
  private final SafePocLinkService pocLinks;

  public GetTopologyCapability(FingerprintRuleCatalog catalog, SafePocLinkService pocLinks) {
    super(
        CODE,
        "查询资产拓扑",
        "查询平台的指纹规则目录与资产统计概览：规则总数、分类分布、与 PoC 的关联情况。"
            + "无必填参数；可选参数 category（按分类过滤）。"
            + "本能力返回的是平台内置规则目录，不读取任何授权目标的数据，也不向目标发包。"
            + "如需查询某个具体目标的指纹结果，请用 invoke_endpoint 调用对应的目标维度端点。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.NONE,
        AiCapabilityLayer.L1);
    this.catalog = catalog;
    this.pocLinks = pocLinks;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("category", property("string", "可选：按指纹分类过滤"));
    return objectSchema(properties, List.of());
  }

  /** 目录概览。 */
  public Map<String, Object> overview(String category) {
    Map<String, Object> snapshot = new LinkedHashMap<>();
    FingerprintRuleCatalog.CatalogInfo info = catalog.info();
    snapshot.put("version", info.version());
    snapshot.put("ruleCount", info.ruleCount());
    snapshot.put("sha256", info.sha256());
    snapshot.put("categoryFilter", category == null ? "" : category.trim());
    snapshot.put("pocLinkServiceAvailable", pocLinks != null);
    return Map.copyOf(snapshot);
  }
}
