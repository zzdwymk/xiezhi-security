package com.bachelor.toolbox.ai.capability;

import java.util.Map;
import java.util.Set;

/**
 * Agent 能力抽象（设计文档 §4.1）。
 *
 * <p>平台的全部可调用面——手工封装的高层能力、自动派生的端点能力、通用端点原语——统一实现本接口，并由 {@link
 * CapabilityRegistry} 登记。治理层 {@code CapabilityGate} 只认本接口，不存在绕过通道。
 *
 * <h2>护栏约定</h2>
 *
 * <p><strong>{@link #targetBindings(Map)} 是本接口最重要的方法</strong>。它声明"本次调用会触及哪些授权目标 ID"，是护栏 L-A
 * 授权校验的唯一判定依据（设计文档 §6.2）。判定依据必须<strong>是"是否触及目标"，而不是 {@link #kind()}</strong>：否则
 * {@code POST /api/tasks} 这类"创建一个会扫描目标的任务"的间接执行能力会因类别是 {@link CapabilityKind#WRITE}
 * 而跳过授权校验。
 *
 * <p>约定：<strong>凡最终会触及授权目标的能力都必须实现该方法</strong>；实现不了的（例如通用端点原语）必须返回 {@link
 * #TARGET_BINDING_UNRESOLVED}，由治理层按 fail-closed 处理，绝不能返回空集冒充"不触及目标"。
 */
public interface AgentCapability {

  /**
   * 目标绑定无法静态解析的哨兵值。
   *
   * <p>用于 {@code invoke_endpoint} 这类参数结构任意、无法保证解析出 {@code targetId} 的能力，以及扫描类能力漏传目标参数的
   * 情况。治理层遇到该值必须 fail-closed（拒绝或转入人工确认），而不是当作"不触及任何目标"放行。
   *
   * <p>该值刻意不是空串，且不会与任何真实目标 ID 冲突，便于治理层用 {@code contains} 判定。
   */
  String TARGET_BINDING_UNRESOLVED = "__UNRESOLVED__";

  /** 唯一标识，全局不可重复。 */
  String code();

  /** 中文名，用于展示与人工确认界面。 */
  String displayName();

  /** 给 LLM 的自然语言描述，应说明用途与边界。 */
  String description();

  /**
   * 参数的 JSON Schema，用于 L-C 参数校验与提示词构建。
   *
   * <p>返回空 Map 表示该能力不接受任何参数。
   */
  Map<String, Object> parameterSchema();

  /** 能力类别。仅用于分类与展示，<strong>不得</strong>作为授权校验依据。 */
  CapabilityKind kind();

  /** 风险等级。 */
  RiskLevel risk();

  /** 是否需要人工确认。 */
  boolean requiresApproval();

  /**
   * 授权边界声明：本能力本次调用会触及哪些授权目标 ID。
   *
   * <h2>三态语义（治理层据此决定是否 fail-closed）</h2>
   *
   * <table border="1">
   *   <caption>返回值语义</caption>
   *   <tr><th>返回</th><th>含义</th><th>护栏 L-A 行为</th></tr>
   *   <tr>
   *     <td><strong>真空集</strong> {@code Set.of()}</td>
   *     <td>该能力<strong>确实不触及</strong>任何授权目标（如 {@code retrieve_project_context} 项目资料检索）</td>
   *     <td>跳过授权校验</td>
   *   </tr>
   *   <tr>
   *     <td><strong>含真实 targetId 的集合</strong></td>
   *     <td>本次调用会触及这些授权目标</td>
   *     <td>对每个 ID 逐个执行范围、端口、有效期校验</td>
   *   </tr>
   *   <tr>
   *     <td><strong>含 {@link #TARGET_BINDING_UNRESOLVED} 的集合</strong></td>
   *     <td>无法从参数解析出目标</td>
   *     <td><strong>必须 fail-closed 拒绝</strong>，不得放行</td>
   *   </tr>
   * </table>
   *
   * <p><strong>为什么需要第三态</strong>：现有 {@code SecurityTool} 的目标由框架注入
   * （{@code execute(AuthorizedTarget target, Map params)}），工具参数里并不含 {@code targetId}。若把"解析不到目标"
   * 一律折叠成空集，扫描类能力就会跳过授权校验，护栏立即 fail-open——这正是设计文档 §6.2 想防住的错误。因此"确定不触及"与
   * "解析不出"必须是两种不同的返回值。
   *
   * @param params 本次调用的实际参数；允许为 {@code null}
   * @return 见上表三态语义
   */
  default Set<String> targetBindings(Map<String, Object> params) {
    return Set.of();
  }

  /**
   * 能力自定义参数校验（端口范围、路径、互斥参数等）。
   *
   * <p>在 JSON Schema 校验之后调用。实现应抛出 {@code ApiException} 表达拒绝。
   *
   * @param params 本次调用的实际参数；允许为 {@code null}
   */
  default void validateParams(Map<String, Object> params) {}
}
