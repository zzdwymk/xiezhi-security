package com.bachelor.toolbox.ai.capability;

import com.bachelor.toolbox.common.ApiException;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * 能力注册表（设计文档 §4.2、§6.4）。
 *
 * <p>汇聚三路能力来源：手工封装的高层能力、自动派生的端点能力、通用端点原语。所有能力都必须在此登记，治理层只通过本注册表查找能力。
 *
 * <p>本类只提供黑名单的<strong>查询</strong>能力，黑名单配置数据由治理层（护栏 L-B）提供，通过构造注入。这样做是为了让"什么被禁止"
 * 这一策略决定集中在一处，而"怎么查"这一机制留在能力层。
 *
 * <p><strong>刻意不标注 {@code @Component}</strong>：本类的构造器需要"能力清单 + 黑名单"两个参数，无法被 Spring 直接实例化。
 * Bean 定义统一放在 {@link AgentCapabilityAutoConfiguration#capabilityRegistry}，并标注
 * {@code @ConditionalOnMissingBean} 供治理层覆盖。
 */
public class CapabilityRegistry {

  private final Map<String, AgentCapability> capabilities = new LinkedHashMap<>();
  private final Set<String> blockedCodes = new TreeSet<>();

  /**
   * @param capabilityList 三路来源汇聚的全部能力
   * @param blockedCodes 初始黑名单（绝对禁止 Agent 调用的能力码），允许为 {@code null}
   */
  public CapabilityRegistry(List<AgentCapability> capabilityList, Set<String> blockedCodes) {
    if (capabilityList != null) {
      for (AgentCapability capability : capabilityList) {
        register(capability);
      }
    }
    if (blockedCodes != null) {
      for (String code : blockedCodes) {
        if (code != null && !code.isBlank()) {
          this.blockedCodes.add(code.trim());
        }
      }
    }
  }

  /** 不配置黑名单的便捷构造器，等价于空黑名单。 */
  public CapabilityRegistry(List<AgentCapability> capabilityList) {
    this(capabilityList, Set.of());
  }

  /**
   * 登记一个能力。
   *
   * @throws IllegalStateException code 为空或重复注册时抛出，避免启动期出现"能力静默丢失"
   */
  public final void register(AgentCapability capability) {
    Objects.requireNonNull(capability, "能力不能为空");
    String code = capability.code();
    if (code == null || code.isBlank()) {
      throw new IllegalStateException("能力注册 code 不能为空");
    }
    if (capabilities.putIfAbsent(code, capability) != null) {
      throw new IllegalStateException("能力 code 重复注册: " + code);
    }
  }

  /** 按 code 查询，不存在时返回空。 */
  public Optional<AgentCapability> find(String code) {
    return code == null ? Optional.empty() : Optional.ofNullable(capabilities.get(code));
  }

  /**
   * 按 code 查询，不存在时抛出 {@link ApiException}。
   *
   * <p>与 {@code SecurityToolRegistry#require} 的错误语义保持一致，便于治理层直接使用。
   */
  public AgentCapability require(String code) {
    AgentCapability capability = code == null ? null : capabilities.get(code);
    if (capability == null) {
      throw new ApiException("未知或未授权的 Agent 能力: " + code);
    }
    return capability;
  }

  /** 列出全部已登记能力，顺序为注册顺序。 */
  public Collection<AgentCapability> all() {
    return List.copyOf(capabilities.values());
  }

  /** 已登记能力的数量。 */
  public int size() {
    return capabilities.size();
  }

  /** 判断能力码是否在黑名单内（护栏 L-B 的能力准入判定）。 */
  public boolean isBlocked(String code) {
    return code != null && blockedCodes.contains(code);
  }

  /** 判断能力是否在黑名单内。 */
  public boolean isBlocked(AgentCapability capability) {
    return capability != null && isBlocked(capability.code());
  }

  /** 当前黑名单快照（只读）。 */
  public Set<String> blockedCodes() {
    return Set.copyOf(blockedCodes);
  }
}
