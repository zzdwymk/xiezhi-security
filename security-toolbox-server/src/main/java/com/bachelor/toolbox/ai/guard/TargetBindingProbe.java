package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import java.lang.reflect.Method;

/**
 * 目标绑定语义探针：判定一个能力是否<strong>显式声明了"我确实不触及授权目标"</strong>。
 *
 * <h2>为什么必须有这个类</h2>
 *
 * <p>设计文档 §6.2 要求"空集"与"哨兵"必须是两种不同的返回。但仅有这两种返回值还不够：能力可以<strong>什么都没声明</strong>就返回空集
 * （{@link AgentCapability#targetBindings} 是 default 方法，默认返回空集）。若护栏把"空集"一律当成合法，那么：
 *
 * <ul>
 *   <li>一个漏实现 {@code targetBindings} 的间接执行能力（如 {@code POST /api/tasks}）会静默跳过 L-A；
 *   <li>一个被错误推断为 {@code SAFE} 的扫描能力同样会静默跳过 L-A（§10 失败模式表："风险等级误判为低"）。
 * </ul>
 *
 * <p>两者都是 fail-open。因此空集的合法性<strong>必须来自显式声明</strong>，而不是来自 {@code risk()} / {@code requiresApproval()}
 * 这些<em>推导</em>出来的值。
 *
 * <h2>判定顺序</h2>
 *
 * <ol>
 *   <li>能力实现了本包的 {@link TargetBindingDeclaration} → 直接采信其显式声明（新能力应优先实现该接口）；
 *   <li>否则反射读取能力上的 {@code targetScope()} 访问器（task-1 的 {@code SecurityToolCapability.TargetScope} 即为此形态），
 *       取值为 {@code NONE} 时视为显式声明"不触及目标"；
 *   <li>否则反射读取 {@code targetBindingsDeclared()} / {@code touchesTargets()} 之类的布尔访问器；
 *   <li>都拿不到 → {@link Declaration#UNKNOWN}，护栏按 fail-closed 处理（空集不合法）。
 * </ol>
 *
 * <p>反射只用于<strong>读取一个枚举/布尔常量</strong>，任何异常都收敛为 {@link Declaration#UNKNOWN}（即拒绝），不存在"反射失败
 * 意外放行"的路径。
 */
public final class TargetBindingProbe {

  /** 能力对"是否触及授权目标"的声明状态。 */
  public enum Declaration {
    /** 显式声明：本能力确实不触及任何授权目标（例如项目资料检索）→ 空集合法。 */
    NONE,
    /** 显式声明：本能力应触及授权目标 → 空集非法，必须 fail-closed。 */
    REQUIRED,
    /** 没有可用声明 → 空集非法（fail-closed），护栏拒绝。 */
    UNKNOWN
  }

  /** 能力可选实现该接口，把"是否触及目标"从运行时返回值提升为类型级声明。 */
  public interface TargetBindingDeclaration {
    /** 见 {@link Declaration}。 */
    Declaration targetBindingDeclaration();
  }

  private TargetBindingProbe() {}

  /** 判定能力的声明状态。永不抛出。 */
  public static Declaration declarationOf(AgentCapability capability) {
    if (capability == null) {
      return Declaration.UNKNOWN;
    }
    if (capability instanceof TargetBindingDeclaration declared) {
      Declaration value = declared.targetBindingDeclaration();
      return value == null ? Declaration.UNKNOWN : value;
    }
    Declaration fromScope = readTargetScope(capability);
    if (fromScope != null) {
      return fromScope;
    }
    Declaration fromBoolean = readBooleanDeclaration(capability);
    return fromBoolean == null ? Declaration.UNKNOWN : fromBoolean;
  }

  /** 空集是否合法：只有显式声明 {@link Declaration#NONE} 才合法。 */
  public static boolean emptyBindingAllowed(AgentCapability capability) {
    return declarationOf(capability) == Declaration.NONE;
  }

  /**
   * 反射读取 {@code targetScope()} 访问器。
   *
   * <p>按枚举常量<strong>名字</strong>匹配而不是按类型匹配，这样护栏不必在编译期依赖能力层的具体适配器类型（设计上护栏只认
   * {@link AgentCapability} 接口）。取值为 {@code NONE} → 不触及目标；取值为 {@code REQUIRED} → 应触及目标；其他未知取值
   * → 返回 {@code null} 落到 UNKNOWN（fail-closed）。
   */
  private static Declaration readTargetScope(AgentCapability capability) {
    Object value = invokeNoArg(capability, "targetScope");
    if (value == null) {
      return null;
    }
    String name = value instanceof Enum<?> constant ? constant.name() : String.valueOf(value);
    return switch (name.trim().toUpperCase(java.util.Locale.ROOT)) {
      case "NONE", "NOT_REQUIRED", "NO_TARGET" -> Declaration.NONE;
      case "REQUIRED", "MANDATORY" -> Declaration.REQUIRED;
      default -> null;
    };
  }

  /** 反射读取布尔型声明访问器。 */
  private static Declaration readBooleanDeclaration(AgentCapability capability) {
    Object declared = invokeNoArg(capability, "targetBindingsDeclared");
    if (declared instanceof Boolean flag) {
      return flag ? Declaration.REQUIRED : Declaration.NONE;
    }
    Object touches = invokeNoArg(capability, "touchesTargets");
    if (touches instanceof Boolean flag) {
      return flag ? Declaration.REQUIRED : Declaration.NONE;
    }
    return null;
  }

  private static Object invokeNoArg(AgentCapability capability, String accessor) {
    try {
      Method method = capability.getClass().getMethod(accessor);
      if (method.getParameterCount() != 0) {
        return null;
      }
      return method.invoke(capability);
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      // 能力没有该访问器，或访问器抛错 → 交由调用方按 UNKNOWN（fail-closed）处理。
      return null;
    }
  }
}
