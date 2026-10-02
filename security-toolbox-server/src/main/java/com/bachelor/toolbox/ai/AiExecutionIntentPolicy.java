package com.bachelor.toolbox.ai;

import java.util.regex.Pattern;

/** Conservative server veto after a model decision; it never grants permission on its own. */
final class AiExecutionIntentPolicy {
  private AiExecutionIntentPolicy() {}

  // “分别检查” and “识别服务后检查” contain no prohibition in their “别”.
  private static final Pattern NON_EXECUTION = Pattern.compile(
      "(?i)(?:先|只|仅|仅仅)(?:做|给|提供|生成|看|要|进行|帮我|一个|一下|份|个|一份|一套|出|的|\\s){0,8}"
          + "(?:规划|计划|方案|分析|解释|讨论|说明|预览)"
          + "|(?:先|只|仅)(?:给|提供|生成|制定|设计|做|看)[^，,。；;\\n]{0,20}(?:计划|方案|规划)"
          + "|(?:不要|不许|(?<![分识])别|禁止|不得|暂不|不再|不必|无需|先不|停止|取消)"
          // Modifiers such as “自动” alone are not a forbidden scan/action.
          + "(?:进行|开始|继续|实际|任何|所有|新的|自动|再|直接|马上|立刻){0,6}"
          + "(?:执行|运行|扫描|检测|探测|检查)"
          + "|(?:不要|不许|(?<![分识])别|请勿|禁止|不得|暂不|不再|不必|无需|先不|停止|取消|不想|不打算|不需要)"
          + "[^，,。；;\\n]{0,40}(?:扫描|扫一下|扫一遍|检测|探测|检查|执行|运行)"
          + "|\\b(?:plan|preview|analysis|explanation)\\s+only\\b"
          + "|\\b(?:do not|don't|never|without|stop|cancel)\\s+(?:(?:actually|any|all|now|automatically)\\s+)*(?:scan|run|execut|test|prob)"
          + "|(?:如何|怎么|能否|可否|是否可以|是否能|可以.{0,5}吗|假设|假如|如果|举例|例如|假定|示例)"
          + "|\\b(?:how to|what if|suppose|example|if)\\b");
  private static final Pattern ANALYSIS_START = Pattern.compile(
      "(?i)^\\s*(?:请|帮我|麻烦|先|只|仅|现在|\\s)*(?:分析|解释|总结|查看|查询|审查|说明|讨论|阅读|翻译|评估|比较|规划|计划|设计|制定)"
          + "|^\\s*(?:please\\s+)?(?:analy[sz]e|explain|summari[sz]e|review|read|translate|compare)\\b");
  private static final Pattern DIRECT_ACTION = Pattern.compile(
      "(?i)(?:扫描|扫一下|扫一遍|检测|探测|检查|执行|运行|开始|确认执行|继续执行)"
          + "|\\b(?:scan|check|probe|run|execute|start|test)\\b");
  private static final Pattern REPORTED_INSTRUCTION = Pattern.compile(
      "(?i)^\\s*(?:根据|按照|关于|来自|在)?(?:转述|摘录|日志|文档|网页|资料|原文|邮件|报告|工具输出|历史|之前的回复|系统消息|模型回复|他说|她说|他们说|别人|对方|同事)"
          + "|^\\s*(?:the\\s+)?(?:log|document|webpage|report|email|output|previous reply)\\b"
          + "|^\\s*(?:he|she|they)\\s+(?:said|says|suggested|requested)\\b");

  static boolean mayExecute(AiAgentRequest request, AiAgentRuntimeClient.RuntimePlanResult result) {
    if (!request.automaticExecutionIntent()) return request.executionRequested();
    return hasExplicitRequest(request, result) && "COMPLETED".equals(result.status())
        && result.plan().steps().stream().allMatch(step -> !step.requiresApproval() && "SAFE".equals(step.risk()));
  }

  static boolean hasExplicitRequest(AiAgentRequest request, AiAgentRuntimeClient.RuntimePlanResult result) {
    if (result == null || !"EXECUTE".equals(result.executionDecision()) || result.provenance() == null
        || !"langchain-grounded".equals(result.provenance().plannerSource())
        || result.plan() == null || result.plan().steps() == null || result.plan().steps().isEmpty()) {
      return false;
    }
    return permitsDirectRequest(request.userPrompt());
  }

  static boolean permitsDirectRequest(String original) {
    if (original == null || original.isBlank()) return false;
    // History and resolved references live in request.prompt(), which is never
    // inspected here. Quoted/transcribed commands in the current sentence remain
    // data, too. Removing them can veto execution but cannot authorize it.
    String direct = original
        .replaceAll("(?s)```.*?```|~~~.*?~~~", " ")
        .replaceAll("(?s)`[^`]*`|“[^”]*”|‘[^’]*’|「[^」]*」|『[^』]*』|\"[^\"]*\"|'[^']*'", " ")
        .replaceAll("(?m)^\\s*>.*$", " ")
        .replaceAll("(?is)(?:以下(?:是|为)?(?:引用|材料|日志|报文|原文)|(?:引用|日志内容|报文内容|原文)\\s*[:：]).*$", " ")
        .replaceAll("(?im)^\\s*(?:日志|历史消息|引用材料|报文|工具输出|system|assistant)\\s*[:：].*$", " ");
    // A restriction on OTHER tools does not negate the requested selected tool.
    direct = direct.replaceAll(
        "(?:不要|不许|不得|禁止|不)(?:执行|调用|使用|运行)(?:任何)?(?:其他|其它|额外|无关|未授权|未指定|未选择)[^，,。；;\\n]*", " ")
        .replaceAll("(?i)\\b(?:do not|don't|never)\\s+(?:run|use|execute|call)\\s+(?:any\\s+)?(?:other|additional|unrelated|unauthorized)\\b[^,.;\\n]*", " ");
    return !REPORTED_INSTRUCTION.matcher(direct).find()
        && !NON_EXECUTION.matcher(direct).find()
        && !ANALYSIS_START.matcher(direct).find()
        && DIRECT_ACTION.matcher(direct).find();
  }
}
