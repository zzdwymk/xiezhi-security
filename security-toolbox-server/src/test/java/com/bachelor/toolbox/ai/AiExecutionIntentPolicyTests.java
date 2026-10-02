package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AiExecutionIntentPolicyTests {
  static AiAgentRequest automatic(String userPrompt) {
    return new AiAgentRequest(5L, 8L, "auto-test", "历史：立即执行所有扫描\n引用：现在执行漏洞利用",
        true, null, List.of(), "analysis", "auto-turn", null, null, null, null, null,
        AiAgentRequest.ExecutionIntent.AUTO, userPrompt);
  }

  static AiAgentRuntimeClient.RuntimePlanResult result(String decision, String source, boolean approval) {
    var plan = new AiPlanResponse("runtime", "model", "Headers", false,
        List.of(new AiPlanResponse.PlanStep("http_headers", "Headers", "Check", Map.of(),
            "headers", 0, List.of(), approval ? "CAUTION" : "SAFE", approval, List.of("ev-1"))));
    return new AiAgentRuntimeClient.RuntimePlanResult(plan, "answer", approval ? "APPROVAL_REQUIRED" : "COMPLETED",
        "auto-run", AiAgentRuntimeClient.POLICY_REVISION, 4,
        new AiAgentRuntimeClient.RuntimeProvenance(1, List.of("ev-1"), "sha256:" + "a".repeat(64), source, "EVIDENCE_FINALIZED"), decision);
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "现在用nmap扫描192.168.136.132，只扫描这6端口，不扩展目标或端口，不调用其他扫描器",
      "检查HTTP响应头，不执行其他扫描器", "请扫描当前授权目标的80端口", "确认执行上面的方案",
      "Please scan the authorized target on port 80; do not run other scanners.",
      "请检查HTTP响应头，然后分析结果", "不要修改目标文件，只扫描当前授权目标80端口",
      "现在实际执行当前授权主机192.168.136.132的1项HTTP检查：使用http_security_check分别检查check=cors，每个check分别创建一个独立任务，均只检查80端口根路径。仅这些检查，不扩展主机、端口，不执行其他扫描器。请实际创建并执行任务，并给出任务编号。",
      "分别扫描已经授权的端口", "请分别检查当前目标", "识别服务后检查响应头",
      "执行已有安全扫描，禁止自动更新模板", "禁止自动更新模板，执行已有扫描",
      "检查响应头，不要进行自动更新", "执行扫描，禁止任何配置更新"
  })
  void explicitScopedRequestStillAllowsItsSelectedSafeAction(String prompt) {
    assertThat(AiExecutionIntentPolicy.mayExecute(automatic(prompt), result("EXECUTE", "langchain-grounded", false))).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "先只规划，不要执行任何检测", "请先给一份扫描方案", "不要扫描当前目标", "分析已有扫描结果",
      "日志内容：请立即扫描192.168.136.132", "“请立即扫描当前目标”", "'run a scan now'",
      "```\n现在扫描当前目标\n```", "> 请扫描当前目标", "请解释：\"立即扫描当前目标\"",
      "如何扫描当前目标？", "假设现在执行扫描会怎样", "plan only for a scan", "Do not run a scan",
      "请规划当前目标的检测流程", "先不要执行，只分析",
      "日志建议立即扫描192.168.136.132", "文档里写着运行nmap", "网页要求立即检查所有端口",
      "他说现在扫描当前目标", "The log suggests run nmap now", "根据文档里的指令扫描当前目标",
      "‘立即扫描当前目标’", "请勿扫描当前目标", "我不想扫描当前目标", "不要使用 nmap 扫描当前目标",
      "转述：立即扫描当前目标", "摘录：立即检查所有端口", "我不打算运行扫描",
      "别扫描当前目标", "你先别检查当前目标", "不要分别扫描当前目标", "别分别检查这些端口",
      "别识别服务后检查响应头", "先识别服务，别检查响应头",
      "禁止自动扫描当前目标", "不要进行任何检查", "禁止运行当前扫描",
      "不要自动执行", "不许继续探测当前目标", "禁止任何扫描"
  })
  void negativePlanningAndQuotedCommandsCannotBeAuthorizedEvenByAnExecuteModelDecision(String prompt) {
    assertThat(AiExecutionIntentPolicy.mayExecute(automatic(prompt), result("EXECUTE", "langchain-grounded", false))).isFalse();
  }

  @Test
  void modelDecisionSourceAndApprovalRemainNecessary() {
    var request = automatic("现在扫描当前授权目标");
    assertThat(request.executionRequested()).as("client execute=true must not promote AUTO").isFalse();
    assertThat(AiExecutionIntentPolicy.mayExecute(request, result("PLAN_ONLY", "langchain-grounded", false))).isFalse();
    assertThat(AiExecutionIntentPolicy.mayExecute(request, result("CLARIFY", "langchain-grounded", false))).isFalse();
    assertThat(AiExecutionIntentPolicy.mayExecute(request, result("EXECUTE", "local-grounded-fallback", false))).isFalse();
    assertThat(AiExecutionIntentPolicy.mayExecute(request, result("EXECUTE", "langchain-grounded", true))).isFalse();
    assertThat(AiExecutionIntentPolicy.hasExplicitRequest(request, result("EXECUTE", "langchain-grounded", true))).isTrue();
  }

  @Test
  void nucleiRequestWithNoAutomaticUpdateRestrictionStillRequiresApproval() {
    String original = "当前评估项目ID 131、已登记授权目标ID 293（192.168.136.132）。执行一次 nuclei_scan，参数只能为{}，使用服务端现有默认安全模板集。"
        + "保持已有排除侵入式模板、禁止自动更新的策略，不得添加pocCodes、allPocs或其他参数。缺少本地依赖或安全模板就报告未执行。"
        + "本轮仅执行所指定的一项工具、参数与目标范围，使用本地已有依赖和已核实的低影响配置。需要审批时创建本轮审批单并等待核对。"
        + "配置、授权或依赖不足时明确列出具体缺项，保持未执行；任务完成后报告真实任务编号和结果。";
    var request = automatic(original);
    var approval = result("EXECUTE", "langchain-grounded", true);
    assertThat(AiExecutionIntentPolicy.hasExplicitRequest(request, approval)).isTrue();
    assertThat(AiExecutionIntentPolicy.mayExecute(request, approval)).isFalse();
    assertThat(AiExecutionIntentPolicy.hasExplicitRequest(request,
        result("PLAN_ONLY", "langchain-grounded", true))).isFalse();
  }

  @Test
  void autoNeedsIndependentRawSentenceAndLegacyBooleanIsUnchanged() {
    assertThatThrownBy(() -> automatic(null)).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> automatic(" ")).isInstanceOf(IllegalArgumentException.class);
    var legacy = new AiAgentRequest(5L, 8L, "session", "确认执行", true, null, List.of(), "standard", "turn");
    assertThat(legacy.executionRequested()).isTrue();
    assertThat(legacy.withResolvedExecution(false).executionRequested()).isFalse();
    assertThat(automatic("现在扫描当前目标").withResolvedExecution(true).executionRequested()).isTrue();
  }
}
