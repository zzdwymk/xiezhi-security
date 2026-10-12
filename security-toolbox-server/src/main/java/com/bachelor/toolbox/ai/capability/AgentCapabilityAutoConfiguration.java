package com.bachelor.toolbox.ai.capability;

import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 把现有 {@link SecurityTool} 接入能力模型（设计文档 §4.2 路线 A 的补充）。
 *
 * <p>现有 14 个安全工具不改一行代码即可成为 {@link AgentCapability}，治理层因此可以统一用 {@link CapabilityRegistry}
 * 查找并约束它们。
 *
 * <p>关于黑名单：本配置<strong>不</strong>定义黑名单数据。黑名单是治理层（护栏 L-B）的策略决定，通过构造注入；此处只保证
 * 在治理层尚未接入时注册表可独立工作（空黑名单）。任务分配上，黑名单配置由 task-2 提供。
 */
@Configuration
public class AgentCapabilityAutoConfiguration {

  /**
   * 能力注册表。
   *
   * <p>以 {@link SecurityToolRegistry} 为唯一工具来源，保证"能被 AI 调用的工具"与"被能力模型登记的工具"始终一致，避免出现
   * 只在一个清单里存在的能力。
   *
   * <p>标注 {@link ConditionalOnMissingBean}：治理层（护栏 L-B）需要注入自己的黑名单数据来构造注册表，定义同名 Bean 即可干净覆盖
   * 本默认实现，无需改动能力层代码。
   */
  @Bean
  @ConditionalOnMissingBean(CapabilityRegistry.class)
  public CapabilityRegistry capabilityRegistry(SecurityToolRegistry toolRegistry) {
    List<AgentCapability> capabilities = new ArrayList<>();
    Set<String> registered = new LinkedHashSet<>();
    for (SecurityTool tool : toolRegistry.all()) {
      SecurityToolCapability capability = SecurityToolCapability.of(tool);
      if (registered.add(capability.code())) {
        capabilities.add(capability);
      }
    }
    return new CapabilityRegistry(capabilities);
  }
}
