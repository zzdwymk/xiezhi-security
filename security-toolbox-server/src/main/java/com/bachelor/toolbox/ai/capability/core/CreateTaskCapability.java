package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code create_task} —— 创建单个安全任务（设计文档 §4.2 路线 A、§6.2 的核心案例）。
 *
 * <p>封装 {@code POST /api/tasks}（{@link TaskService#create}）。
 *
 * <h2>为什么这个能力是护栏设计的关键测试点</h2>
 *
 * <p>{@code POST /api/tasks} 在 HTTP 语义上只是"写一条记录"（{@link CapabilityKind#WRITE}），但它创建的任务会
 * <strong>异步对 {@code targetId} 执行 {@code toolCode} 指定的扫描/探测</strong>。设计文档 §6.2 正是用这个例子说明：
 * 授权校验若按 {@code kind()} 判定，间接执行能力会整条跳过 L-A。
 *
 * <p>因此本能力：
 *
 * <ol>
 *   <li>{@code targetId} 是<strong>必填</strong>参数，并进入 {@link BindingMode#RESOLVED} 的解析路径；
 *   <li>解析不到目标时返回哨兵，护栏 fail-closed 拒绝，而不是"当作不触及目标"放行；
 *   <li>{@code requiresApproval = true}：创建的任务会对授权目标发起实际执行（§6.6 的 {@code REQUIRED} 档）。
 * </ol>
 *
 * <h2>与 {@code EndpointParameterPolicy} 的分工</h2>
 *
 * <p>本能力只做"能力自身可判定"的检查（参数存在性、类型、目标 ID 可解析）。工具参数的深度校验（端口 ⊆ 授权端口、
 * MSF 模块前缀、PoC 编号范围）属于护栏的 L-C' 层（{@code EndpointParameterPolicy}），本层不重复实现，避免出现两套
 * 互相漂移的规则。
 */
@Component
public class CreateTaskCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "create_task";

  private final TaskService tasks;
  private final SecurityToolRegistry toolRegistry;

  public CreateTaskCapability(TaskService tasks, SecurityToolRegistry toolRegistry) {
    super(
        CODE,
        "创建安全任务",
        "为指定项目与授权目标创建一个安全工具任务并立即进入执行队列。"
            + "参数：projectId、targetId（本次任务会扫描的授权目标，必填且必须已授权）、"
            + "toolCode（安全工具代码，如 nmap_service_scan / http_headers / nuclei_scan）、"
            + "parameters（工具参数对象，如 ports、mode、pocCodes）。"
            + "本能力创建的任务会对授权目标发起实际执行，因此需要人工确认；"
            + "目标必须已授权且在有效期内，端口必须在授权端口范围内，否则护栏拒绝。",
        CapabilityKind.WRITE,
        RiskLevel.SENSITIVE,
        true,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.tasks = tasks;
    this.toolRegistry = toolRegistry;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("projectId", integerProperty(1, "项目 ID；省略时由平台按目标归属推断"));
    properties.put("targetId", integerProperty(1, "本次任务会扫描的授权目标 ID，用于护栏 L-A 授权校验"));
    properties.put("toolCode", property("string", "安全工具代码，须为平台已注册的工具"));
    properties.put("parameters", property("object", "工具参数对象；端口等取值会在护栏 L-C' 层与授权范围比对"));
    return objectSchema(properties, List.of("targetId", "toolCode"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "targetId");
    String toolCode = requireText(params, "toolCode");
    Map<String, Object> parameters = optionalMap(params, "parameters");
    Object rawParameters = params.get("parameters");
    if (rawParameters != null && !(rawParameters instanceof Map)) {
      throw new ApiException("参数 parameters 必须是 JSON 对象");
    }
    // 工具码与工具参数的取值白名单：复用 ToolParameterPolicy（与 dispatch 层规则集对齐，并有漂移断言保护）。
    //
    // 为什么这一层必须校验，而不是"交给下游 TaskService.create"：
    //   1) 拒绝理由的精确性——护栏 L-C 的审计要能记录"能力层拒绝了什么"，依赖下游会让审计记成"通过"而实际被拒，
    //      审计与事实不符（§9.5 的越权拦截率归因正依赖这个）；
    //   2) 下游路径一旦重构（例如 TaskService 换实现），这层保护会静默消失，而能力层的 Javadoc 仍声称校验过；
    //   3) 与 guard-verifier 发现的 D-1..D-6 属同一模式——"校验覆盖不全"的缺口不会报错，只会静默降低防护等级。
    ToolParameterPolicy.validate(toolCode, parameters);
    // 额外的注册表存在性校验：ToolParameterPolicy 的白名单是"AI 可执行工具"这一子集，
    // 而平台注册表可能还包含非 AI 工具。这里以注册表为最终事实来源，防止能力层放行注册表里根本不存在的码。
    if (toolRegistry != null
        && toolRegistry.all().stream().noneMatch(tool -> tool.code().equals(toolCode))) {
      throw new ApiException("未知的安全工具代码: " + toolCode + "（须为平台已注册的工具）");
    }
  }

  /** 创建任务。 */
  public SecurityTask create(Long projectId, Long targetId, String toolCode, Map<String, Object> parameters)
      throws JsonProcessingException {
    return tasks.create(new CreateTaskRequest(projectId, targetId, toolCode, parameters));
  }
}
