package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code retest_finding} —— 对一条漏洞发现发起复测（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code POST /api/findings/{id}/retest} 的语义（{@link TaskService#createRetest}）。
 *
 * <h2>目标绑定：{@link BindingMode#RESOLVED}</h2>
 *
 * <p>复测<strong>就是重新对目标发起一次实际探测</strong>（用原始规则重新打一遍），是最典型的"触及授权目标"的动作。
 * 它的 {@code kind} 是 {@link CapabilityKind#EXECUTE}，{@code requiresApproval = true}（§6.6："对授权目标发起实际执行"）。
 *
 * <p>{@code targetId} 必填且进入 L-A 校验：复测会真实发包，若跳过授权校验，Agent 就能借复测之名对任意目标发起扫描。
 * 复测任务的工具与参数来自原始任务/发现记录，因此这里额外要求调用方声明目标，让护栏有可校验的对象。
 */
@Component
public class RetestFindingCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "retest_finding";

  private final FindingRepository findings;
  private final TaskService tasks;

  public RetestFindingCapability(FindingRepository findings, TaskService tasks) {
    super(
        CODE,
        "复测漏洞发现",
        "对一条漏洞发现发起复测：用原始检测规则对授权目标重新执行一次探测，并记录复测次数与结论。"
            + "参数：findingId（发现记录 ID）、targetId（该发现所属的授权目标 ID，必填——复测会真实发包）。"
            + "复测会对授权目标发起实际执行，因此需要人工确认，且目标必须已授权、在有效期内。",
        CapabilityKind.EXECUTE,
        RiskLevel.SENSITIVE,
        true,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.findings = findings;
    this.tasks = tasks;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("findingId", integerProperty(1, "要复测的漏洞发现记录 ID"));
    properties.put("targetId", integerProperty(1, "该发现所属的授权目标 ID；复测会真实发包到该目标"));
    properties.put("projectId", integerProperty(1, "可选：项目 ID；省略时由平台按任务归属推断"));
    return objectSchema(properties, List.of("findingId", "targetId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "findingId");
    requirePositiveLong(params, "targetId");
  }

  /**
   * 发起复测：创建一条 RETEST 任务并回填复测计数。
   *
   * <p>复用 {@link TaskService#createRetest} 而不是自己拼任务，保证"经能力层复测"与"经 REST 复测"走完全相同的
   * 校验与审计路径——否则能力层就成了一个校验更弱的旁路（§6.5 的"不是特权通道"原则）。
   */
  public SecurityTask retest(Long findingId, Long projectId, Long targetId)
      throws JsonProcessingException {
    Finding finding =
        findings.findById(findingId).orElseThrow(() -> new ApiException("漏洞记录不存在"));
    if (finding.getTaskId() == null) {
      throw new ApiException("该漏洞记录没有关联的原始任务，无法复测");
    }
    SecurityTask retestTask =
        tasks.createRetest(
            new CreateTaskRequest(projectId, targetId, finding.getSourceTool(), Map.of()),
            finding.getRuleCode(),
            finding.getVulnerabilityCode(),
            finding.getTaskId(),
            finding.getId());
    finding.setRetestCount(finding.getRetestCount() + 1);
    finding.setVerifiedTaskId(retestTask.getId());
    findings.save(finding);
    return retestTask;
  }
}
