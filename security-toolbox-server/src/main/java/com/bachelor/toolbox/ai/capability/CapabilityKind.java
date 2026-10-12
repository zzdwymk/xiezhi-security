package com.bachelor.toolbox.ai.capability;

/**
 * 能力类别。
 *
 * <p>注意：类别<strong>不</strong>用于判定是否需要授权校验。设计文档 §6.2 指出，按 {@code kind()} 判定会被"间接执行"能力绕过
 * （例如创建一个会扫描目标的任务，其类别是 {@link #WRITE} 却实际触及目标）。授权校验的唯一依据是
 * {@link AgentCapability#targetBindings(java.util.Map)}。
 */
public enum CapabilityKind {
  /** 只读查询，不产生副作用。 */
  READ,
  /** 数据写入（创建/更新/删除平台对象）。 */
  WRITE,
  /** 对目标执行动作（扫描/探测/利用）。 */
  EXECUTE,
  /** 系统管理（设置、依赖、关机）。 */
  ADMIN
}
