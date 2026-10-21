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
          + "(?:执行|运行|扫描|检测|探测|检查|跑|测|查|扫)"
          + "|(?:不要|不许|(?<![分识])别|请勿|禁止|不得|暂不|不再|不必|无需|先不|停止|取消|不想|不打算|不需要)"
          + "[^，,。；;\\n]{0,40}(?:扫描|扫一?下|扫一遍|检测|探测|检查|执行|运行|跑一?下|测一?下|查一?下)"
          + "|\\b(?:plan|preview|analysis|explanation)\\s+only\\b"
          + "|\\b(?:do not|don't|never|without|stop|cancel)\\s+(?:(?:actually|any|all|now|automatically)\\s+)*(?:scan|run|execut|test|prob)"
          + "|(?:如何|怎么|能否|可否|是否可以|是否能|可以.{0,5}吗|假设|假如|如果|举例|例如|假定|示例)"
          + "|\\b(?:how to|what if|suppose|example|if)\\b");
  private static final Pattern ANALYSIS_START = Pattern.compile(
      "(?i)^\\s*(?:请|帮我|麻烦|先|只|仅|现在|\\s)*(?:分析|解释|总结|查看|查询|审查|说明|讨论|阅读|翻译|评估|比较|规划|计划|设计|制定)"
          + "|^\\s*(?:please\\s+)?(?:analy[sz]e|explain|summari[sz]e|review|read|translate|compare)\\b");
  private static final Pattern DIRECT_ACTION = Pattern.compile(
      "(?i)(?:扫描|扫一?下|扫一遍|检测|探测|检查|执行|运行|开始|确认执行|继续执行|跑一?下|跑一遍|测一?下|测一遍|查一?下)"
          + "|(?:看看|看一?下)[^，,。；;\\n]{0,12}(?:目标|端口|服务|站点|网站|响应头)"
          + "|\\b(?:scan|check|probe|run|execute|start|test)\\b");
  /**
   * A short standalone confirmation ("确认" "那就用" "同意" "按这个来" "执行吧") refers to the
   * single plan the assistant just produced; the model resolves it against that plan. Only a
   * whole-message confirmation counts — the same words inside a longer sentence still need an
   * explicit action verb, and any negation elsewhere still vetoes via {@link #NON_EXECUTION}.
   */
  private static final Pattern SHORT_CONFIRMATION = Pattern.compile(
      "(?i)^(?:请\\s*)?(?:继续|继续吧|继续处理|继续原计划|继续上面的|接着|接着来|接着做|往下做|go ahead|proceed|continue|"
          + "就按这个|按你说的来|照这个来|好|好吧|好的|行|行吧|可以|可以了|确认|确认执行|同意|同意执行|就用|就用这个|就这个|那就用|"
          + "按这个|按这个来|按计划|照这个|这样执行|这么办|执行吧|开始吧|去执行|跑吧|干吧|没问题|ok|OK|Ok|okay)\\s*[吧呢啊。.!！]?$");
  private static final Pattern REPORTED_INSTRUCTION = Pattern.compile(
      "(?i)^\\s*(?:根据|按照|关于|来自|在)?(?:转述|摘录|日志|文档|网页|资料|原文|邮件|报告|工具输出|历史|之前的回复|系统消息|模型回复|他说|她说|他们说|别人|对方|同事)"
          + "|^\\s*(?:the\\s+)?(?:log|document|webpage|report|email|output|previous reply)\\b"
          + "|^\\s*(?:he|she|they)\\s+(?:said|says|suggested|requested)\\b");
  private static final String REVISION_VERB =
      "(?:加上|加个|加一个|加一项|添加|增加|新增|追加|补上|补充|移除|去掉|删掉|删除|删去|修改|更改|调整|改为|改成|换成|替换|重新规划|重做方案"
          + "|降低|调低|调高|提高|减少|缩小|(?:降|调|设|升|减|提)(?:到|成|为)"
          + "|\\b(?:add|append|include|remove|drop|change|adjust|revise|replace|replan|lower|reduce|increase|set)\\b)";
  private static final Pattern REVISION = Pattern.compile("(?i)" + REVISION_VERB);
  private static final String PLAN_OBJECT =
      "(?:目录|路径|端口|服务|指纹|响应头|证书|TLS|HTTP|Nmap|Nuclei|Afrog|Xray|ZAP|Fscan|dir_scan|[a-z]+_scan)";
  private static final Pattern ACTION_SPECIFICATION = Pattern.compile(
      "(?i)(?:扫(?:描|一?下|一遍)?|检测|探测|检查|识别|枚举)[^，,。；;\\n]{0,24}" + PLAN_OBJECT
          + "|" + PLAN_OBJECT + "[^，,。；;\\n]{0,16}(?:扫(?:描|一?下|一遍)?|检测|探测|检查|跑一?下|跑一遍)");
  private static final Pattern PARAMETER_REVISION = Pattern.compile(
      "(?i)(?:并发(?:数)?|线程(?:数)?|深度|超时|字典|端口|concurrency|workers|depth|timeout|dictionary|ports)"
          + "\\s*(?:(?:降|调|改|减|升|设|提|换)[^，,。；;\\n]{0,8}(?:到|成|为|用)?\\s*\\S+|少点|低点|小点|大点|多点)"
          + "|\\b(?:set|lower|reduce|increase)\\s+(?:concurrency|workers|depth|timeout|ports)\\s+(?:to\\s+)?\\S+");
  private static final Pattern PLAN_REFERENCE = Pattern.compile(
      "(?i)^\\s*(?:请|现在|就|那|\\s)*(?:确认|同意|按|照|继续|接着|依照|按照|proceed|continue|go ahead)");
  private static final Pattern NON_REVISION = Pattern.compile(
      "(?i)(?:不要|不许|(?<![分识])别|请勿|禁止|不得|无需|不必|先不|不想|不打算)[^，,。；;\\n]{0,24}" + REVISION_VERB
          + "|\\b(?:do not|don't|never|without)\\b[^,.;\\n]{0,24}" + REVISION_VERB
          + "|(?:如何|怎么|能否|可否|是否|假设|假如|如果|举例|例如|示例)"
          + "|\\b(?:how to|what if|suppose|example|if)\\b");
  private static final Pattern REVISION_ANALYSIS_START = Pattern.compile(
      "(?i)^\\s*(?:请|帮我|麻烦|先|只|仅|现在|\\s)*(?:分析|解释|总结|查看|查询|审查|说明|讨论|阅读|翻译|评估|比较)"
          + "|^\\s*(?:please\\s+)?(?:analy[sz]e|explain|summari[sz]e|review|read|translate|compare)\\b");

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
    return hasModelPlanRelation(result) ? permitsModelRequest(request.userPrompt()) : permitsDirectRequest(request.userPrompt());
  }

  static boolean hasModelPlanRelation(AiAgentRuntimeClient.RuntimePlanResult result) {
    return result != null && result.provenance() != null
        && "langchain-grounded".equals(result.provenance().plannerSource())
        && java.util.Set.of("COMPLETED", "APPROVAL_REQUIRED").contains(java.util.Objects.toString(result.status(), ""))
        && java.util.Set.of("NEW", "CONTINUE", "REVISE").contains(java.util.Objects.toString(result.planRelation(), "NONE"));
  }

  /** The model resolves positive intent; local rules only veto unsafe linguistic evidence. */
  private static boolean permitsModelRequest(String original) {
    String direct = directUserText(original);
    if (direct.isBlank()) return false;
    direct = direct.replaceFirst("^\\s*(?:你)?(?:能不能|能否|可以|能)\\s*(?:帮我|给我|替我|为我)\\s*", "请");
    direct = direct.replaceAll("(?:不要|不许|不得|禁止|不)(?:执行|调用|使用|运行)(?:任何)?(?:其他|其它|额外|无关|未授权|未指定|未选择)[^，,。；;\\n]*", " ");
    return !NON_EXECUTION.matcher(direct).find() && !ANALYSIS_START.matcher(direct).find();
  }

  static boolean permitsModelRevision(String original, AiAgentRuntimeClient.RuntimePlanResult result) {
    if (!hasModelPlanRelation(result) || !java.util.Set.of("NEW", "REVISE").contains(result.planRelation())) return false;
    String direct = directUserText(original);
    // A continuation must never acquire revision rights from a contradictory model label.
    return !direct.isBlank() && !SHORT_CONFIRMATION.matcher(direct.strip()).find()
        && (!PLAN_REFERENCE.matcher(direct).find() || permitsPlanRevision(direct))
        && !REVISION_ANALYSIS_START.matcher(direct).find()
        && !NON_REVISION.matcher(direct).find()
        && (!NON_EXECUTION.matcher(direct).find() || permitsPlanRevision(direct));
  }

  static boolean permitsDirectRequest(String original) {
    String direct = directUserText(original);
    if (direct.isBlank()) return false;
    direct = direct.replaceFirst("^\\s*(?:你)?(?:能不能|能否|可以|能)\\s*(?:帮我|给我|替我|为我)\\s*", "请");
    // A restriction on OTHER tools does not negate the requested selected tool.
    direct = direct.replaceAll(
        "(?:不要|不许|不得|禁止|不)(?:执行|调用|使用|运行)(?:任何)?(?:其他|其它|额外|无关|未授权|未指定|未选择)[^，,。；;\\n]*", " ")
        .replaceAll("(?i)\\b(?:do not|don't|never)\\s+(?:run|use|execute|call)\\s+(?:any\\s+)?(?:other|additional|unrelated|unauthorized)\\b[^,.;\\n]*", " ");
    return !NON_EXECUTION.matcher(direct).find()
        && !ANALYSIS_START.matcher(direct).find()
        && (DIRECT_ACTION.matcher(direct).find() || SHORT_CONFIRMATION.matcher(direct.strip()).find()
            || permitsPlanRevision(direct));
  }

  /** Permission to propose a new plan is not permission to execute it. */
  static boolean permitsPlanRevision(String original) {
    String direct = directUserText(original);
    return !direct.isBlank() && !REVISION_ANALYSIS_START.matcher(direct).find()
        && !NON_REVISION.matcher(direct).find()
        && (REVISION.matcher(direct).find() || PARAMETER_REVISION.matcher(direct).find()
            || (!PLAN_REFERENCE.matcher(direct).find() && !NON_EXECUTION.matcher(direct).find()
                && ACTION_SPECIFICATION.matcher(direct).find()));
  }

  private static String directUserText(String original) {
    if (original == null || original.isBlank()) return "";
    // History and resolved references live in request.prompt(), which is never
    // inspected here. Quoted/transcribed commands in the current sentence remain
    // data, too. Removing them can veto execution but cannot authorize it.
    String direct = original
        .replaceAll("(?s)```.*?```|~~~.*?~~~", " ")
        .replaceAll("(?s)`[^`]*`|“[^”]*”|‘[^’]*’|「[^」]*」|『[^』]*』|\"[^\"]*\"|'[^']*'", " ")
        .replaceAll("(?m)^\\s*>.*$", " ")
        .replaceAll("(?is)(?:以下(?:是|为)?(?:引用|材料|日志|报文|原文)|(?:引用|日志内容|报文内容|原文)\\s*[:：]).*$", " ")
        .replaceAll("(?im)^\\s*(?:日志|历史消息|引用材料|报文|工具输出|system|assistant)\\s*[:：].*$", " ");
    return REPORTED_INSTRUCTION.matcher(direct).find() ? "" : direct;
  }
}
