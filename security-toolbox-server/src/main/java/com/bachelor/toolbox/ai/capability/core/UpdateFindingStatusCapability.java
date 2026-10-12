package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code update_finding_status} —— 更新漏洞发现的处置状态（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code PUT /api/findings/{id}/status} 的状态机语义（与 {@code FindingController#updateStatus} 保持一致的白名单：
 * {@code OPEN} / {@code CONFIRMED} / {@code FALSE_POSITIVE} / {@code FIXED}）。
 *
 * <h2>目标绑定：{@link BindingMode#RESOLVED}</h2>
 *
 * <p>直觉上"改一条记录的字段"似乎不触及目标，但这个直觉是错的：
 *
 * <ul>
 *   <li>把一条发现标记为 {@code FALSE_POSITIVE} 会<strong>把它从报告中移除</strong>——这是对安全结论的实质性修改，
 *       且直接影响"哪些目标被认为存在漏洞"；
 *   <li>它改变的是<strong>针对某个授权目标的评估结论</strong>，因此本次调用确实"触及"该目标。
 * </ul>
 *
 * <p>若按 {@code kind = WRITE} 就跳过授权校验（§6.2 要修正的错误），Agent 可以批量把任意目标上的发现改成误报，
 * 从而让一次真实的越权扫描在报告里"消失"。因此 {@code targetId} 为必填参数并进入 L-A 校验。
 *
 * <p>等级为 {@link RiskLevel#SENSITIVE} 而非 {@code DESTRUCTIVE}：状态是可逆的（可以再改回来），且平台有审计留痕。
 */
@Component
public class UpdateFindingStatusCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "update_finding_status";

  /** 与 {@code FindingController} 保持一致的状态白名单。 */
  public static final List<String> ALLOWED_STATUSES =
      List.of("OPEN", "CONFIRMED", "FALSE_POSITIVE", "FIXED");

  private final FindingRepository findings;

  public UpdateFindingStatusCapability(FindingRepository findings) {
    super(
        CODE,
        "更新漏洞处置状态",
        "更新一条漏洞发现的处置状态。参数：findingId（发现记录 ID）、"
            + "status（OPEN / CONFIRMED / FALSE_POSITIVE / FIXED）、"
            + "targetId（该发现所属的授权目标 ID，必填——状态变更会改变该目标的评估结论）。"
            + "把发现标记为 FALSE_POSITIVE 会使其从报告中移除，因此本能力需要对目标做授权校验。",
        CapabilityKind.WRITE,
        RiskLevel.SENSITIVE,
        false,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.findings = findings;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("findingId", integerProperty(1, "漏洞发现记录 ID"));
    properties.put("status", enumProperty(ALLOWED_STATUSES, "目标处置状态"));
    properties.put("targetId", integerProperty(1, "该发现所属的授权目标 ID，用于护栏 L-A 授权校验"));
    return objectSchema(properties, List.of("findingId", "status", "targetId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "findingId");
    requirePositiveLong(params, "targetId");
    String status = requireText(params, "status").toUpperCase(java.util.Locale.ROOT);
    if (!ALLOWED_STATUSES.contains(status)) {
      throw new ApiException("漏洞状态仅支持 " + String.join("、", ALLOWED_STATUSES));
    }
  }

  /** 更新状态。 */
  public Finding updateStatus(Long findingId, String status) {
    Finding finding =
        findings.findById(findingId).orElseThrow(() -> new ApiException("漏洞记录不存在"));
    finding.setStatus(status.trim().toUpperCase(java.util.Locale.ROOT));
    return findings.save(finding);
  }
}
