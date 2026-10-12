package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import jakarta.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 把手工封装的核心能力<strong>增量注册</strong>进共享的 {@link CapabilityRegistry}。
 *
 * <h2>为什么必须这样装配：一次实测证明的"静默丢失"</h2>
 *
 * <p>本任务最初按设计文档 §4.2 的"做法 A"实现——每个能力做成 {@code @Component}，期望"Spring 自动把类型为
 * {@code AgentCapability} 的独立 Bean 汇总给注册表"。容器测试证明<strong>这条路在本项目里不成立</strong>：
 *
 * <pre>
 * 注册表 size = 182
 * 容器里 AgentCapability 类型 Bean 数 = 25      ← 24 个核心能力 Bean 全都创建成功了
 * 注册表里能找到 create_task = false            ← 但注册表一个都没看到
 * </pre>
 *
 * <p><strong>根因</strong>：{@code AgentCapabilityAutoConfiguration#capabilityRegistry} 的签名是
 * {@code capabilityRegistry(SecurityToolRegistry toolRegistry)}——它<strong>手工遍历 {@code toolRegistry.all()}</strong>
 * 拼装能力列表，<strong>根本不接收 {@code List<AgentCapability>} 构造参数</strong>。因此"@Component 能力会被自动汇总"
 * 这一前提不成立：Bean 确实存在，但没有任何代码把它们喂给注册表。
 *
 * <p>端点能力（路线 B）之所以能进去，是因为 {@code EndpointCapabilityScanner} 在 {@code @PostConstruct} 里
 * <strong>显式调用</strong>了 {@code register()}。本类对核心能力采用<strong>完全相同的机制</strong>——这条路已被
 * 实测证明可行（task-3 由此得到 182 个能力）。
 *
 * <h2>为什么不用"让注册表工厂接收 {@code List<AgentCapability>}"</h2>
 *
 * <p>那是更"自然"的修法，但会立刻引爆一个已记录的循环依赖（见 {@code AgentCapabilityGuardConfiguration:39-42}）：
 *
 * <pre>
 * capabilityRegistry → List&lt;AgentCapability&gt; → invokeEndpointCapability → CapabilityRegistry → ↺
 * </pre>
 *
 * <p>{@code invokeEndpointCapability} 本身就是 {@code List<AgentCapability>} 的一员，却又需要
 * {@code CapabilityRegistry}。guard-dev 已实测：{@code @Primary} 无效、{@code @Lazy} 也打不破这个环。
 *
 * <p>本类的注入是<strong>安全的</strong>：它只注入 {@link AbstractCoreCapability}（本包的能力，全部是叶子节点，
 * 不依赖注册表），而不是宽泛的 {@code List<AgentCapability>}，因此<strong>不参与</strong>上面那个环。
 *
 * <h2>幂等保护</h2>
 *
 * <p>{@code CapabilityRegistry#register} 在 <strong>code 重复时抛 {@code IllegalStateException}</strong>
 * （这是刻意的：能力码重复意味着"两个能力互相覆盖"，必须启动失败）。因此本类用 {@link AtomicBoolean} 保证只推一次，
 * 并且<strong>逐项 {@code find()} 预检</strong>——即使将来出现重复调用（例如测试手工触发、或 Spring 在某些配置下
 * 重复初始化），也不会因为"已存在"而让应用启动失败。预检与 {@code AtomicBoolean} 是双保险：
 * 前者防"同一进程内重复推入"，后者防"并发重复推入"。
 */
@Component
public class CoreCapabilityPublisher {

  private static final Logger log = LoggerFactory.getLogger(CoreCapabilityPublisher.class);

  private final CapabilityRegistry capabilityRegistry;
  private final List<AbstractCoreCapability> coreCapabilities;
  private final AtomicBoolean published = new AtomicBoolean(false);

  /**
   * @param capabilityRegistry 共享注册表（不新建、不替换——替换会让 SecurityTool 能力消失）
   * @param coreCapabilities 本包的手工封装能力。刻意收窄到 {@link AbstractCoreCapability} 而不是
   *     {@code List<AgentCapability>}：后者会把 {@code invoke_endpoint} 也拉进来，形成循环依赖
   */
  public CoreCapabilityPublisher(
      CapabilityRegistry capabilityRegistry, List<AbstractCoreCapability> coreCapabilities) {
    this.capabilityRegistry = capabilityRegistry;
    this.coreCapabilities = coreCapabilities == null ? List.of() : List.copyOf(coreCapabilities);
  }

  /**
   * 启动时把核心能力推入注册表。
   *
   * <p>时序说明：本方法在 refresh 期间执行，早于 {@code EndpointCapabilityScanner} 的端点推入。两者互不依赖，
   * 顺序无关紧要——护栏是在<strong>请求时</strong>查注册表，而不是在构造时。
   */
  @PostConstruct
  public void publish() {
    int added = publishCoreCapabilities();
    log.info(
        "核心能力已并入 CapabilityRegistry：新增 {} 个（本包声明 {} 个），注册表总数 {} 个",
        added,
        coreCapabilities.size(),
        capabilityRegistry.size());
  }

  /**
   * 执行推入，返回本次新增数量。
   *
   * <p>幂等：重复调用返回 0，不抛异常。可供测试手工触发。
   */
  public int publishCoreCapabilities() {
    if (!published.compareAndSet(false, true)) {
      return 0;
    }
    int added = 0;
    for (AbstractCoreCapability capability : coreCapabilities) {
      // 逐项预检：已存在则跳过而不是抛异常，保证重复调用不会导致启动失败。
      if (capabilityRegistry.find(capability.code()).isPresent()) {
        continue;
      }
      capabilityRegistry.register(capability);
      added++;
    }
    return added;
  }

  /** 本包声明的核心能力（只读，供容器测试断言清单）。 */
  public List<AgentCapability> declaredCapabilities() {
    return List.copyOf(new ArrayList<>(coreCapabilities));
  }

  /** 是否已完成推入。 */
  public boolean isPublished() {
    return published.get();
  }
}
