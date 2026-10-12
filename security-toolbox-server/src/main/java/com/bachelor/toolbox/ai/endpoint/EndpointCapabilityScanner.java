package com.bachelor.toolbox.ai.endpoint;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import jakarta.annotation.PostConstruct;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * 端点能力自动派生扫描器（设计文档 §4.2 路线 B）。
 *
 * <p>Bean 名固定为 {@code endpointCapabilityScanner}。
 *
 * <p>启动时读取 {@link RequestMappingHandlerMapping} 的全部映射，为每个 (HTTP 方法, 路径模板) 生成一个
 * {@link EndpointCapability}，登记进 {@link EndpointRegistry}；随后在 {@code @PostConstruct} 末尾把结果
 * <strong>增量推入</strong>共享的 {@link CapabilityRegistry}，使护栏能看到这些端点能力。
 *
 * <h2>为什么用增量推入而不是构造注入</h2>
 *
 * <p>端点数量由运行期扫描 MVC 映射决定，而 {@code RequestMappingHandlerMapping} 只在容器 refresh 末尾才可用；
 * {@code CapabilityRegistry} 却在 refresh 期间就实例化并把能力列表 copy 进内部 Map。两个时间窗没有交集，
 * 因此构造注入无法容纳端点能力（实测四种写法都只得到 14 个 SecurityTool 能力）。详见
 * {@link EndpointCapabilityConfiguration} 的类注释与实测表格。
 *
 * <h2>为什么用 {@link ObjectProvider} 延迟取 {@code RequestMappingHandlerMapping}</h2>
 *
 * <p>扫描器必须在<strong>全部控制器注册完成之后</strong>执行。Spring MVC 的 {@code RequestMappingHandlerMapping} 会
 * 侦听 {@code ContextRefreshedEvent} 并完成 {@code afterPropertiesSet()}，其映射表在 Bean 初始化阶段可能尚未填满。因此：
 *
 * <ul>
 *   <li>用 {@link ObjectProvider} 而不是构造器直接注入——避免在 MVC 初始化链上形成循环依赖；
 *   <li>扫描在 {@link PostConstruct}（即本 Bean 初始化时）执行，此时 {@code RequestMappingHandlerMapping} 已被实例化
 *       并完成 {@code afterPropertiesSet()}（它在本 Bean 之前初始化），映射表已可用。
 * </ul>
 *
 * <p>{@link #refresh()} 可供测试或运行期重新扫描，但正常情况下不需要调用。
 *
 * <h2>能力码冲突</h2>
 *
 * <p>{@link EndpointCapability#codeOf} 是单射的，但若业务上出现同方法同路径的重复映射，或两条路径归一化到同一个能力码，
 * 本扫描器会<strong>保留先登记者并记录警告</strong>，而不是让整个应用启动失败——端点派生是"尽力覆盖"的机制，
 * 一条冲突不应导致平台不可用。冲突详情保留在 {@link #conflicts()} 中供验收检查。
 *
 * <h2>人工校准</h2>
 *
 * <p>§4.2 要求"推断结果写入配置文件，支持人工校准高危项"。本类提供 {@link #setRiskOverrides} 作为校准入口，扫描时套用；
 * 校准数据由运维/配置层提供，本类不绑定具体配置格式，避免在能力层引入配置解析。
 */
@Component("endpointCapabilityScanner")
public class EndpointCapabilityScanner {

  private static final Logger log = LoggerFactory.getLogger(EndpointCapabilityScanner.class);

  private final ObjectProvider<RequestMappingHandlerMapping> handlerMappingProvider;
  private final EndpointRegistry registry;
  /** 人工校准表：{@code "METHOD /path/template"} → 覆盖后的风险等级与确认要求。 */
  private final Map<String, RiskOverride> riskOverrides = new LinkedHashMap<>();

  /** 能力码 → 端点能力，用于检测冲突。 */
  private final Map<String, EndpointCapability> byCode = new LinkedHashMap<>();

  /** 冲突记录：能力码 → 被丢弃的端点描述。 */
  private final Map<String, List<String>> conflicts = new TreeMap<>();

  /** 扫描过程中被跳过的映射及原因，供验收报告"覆盖率"一节使用。 */
  private final Map<String, String> skipped = new TreeMap<>();

  private final AtomicBoolean scanned = new AtomicBoolean(false);

  /** 是否已把端点能力增量并入 {@link CapabilityRegistry}（幂等保护）。 */
  private final AtomicBoolean published = new AtomicBoolean(false);

  /** 共享的能力注册表（task-1 的单例）。允许为 {@code null}：单元测试只关心派生逻辑。 */
  private final CapabilityRegistry capabilityRegistry;

  public EndpointCapabilityScanner(
      ObjectProvider<RequestMappingHandlerMapping> handlerMappingProvider,
      EndpointRegistry registry,
      CapabilityRegistry capabilityRegistry) {
    this.handlerMappingProvider = handlerMappingProvider;
    this.registry = registry;
    this.capabilityRegistry = capabilityRegistry;
  }

  /**
   * 人工校准的风险覆盖。
   *
   * @param method HTTP 方法
   * @param pathTemplate 路径模板
   * @param risk 覆盖后的风险等级
   * @param requiresApproval 覆盖后的确认要求
   */
  public void setRiskOverrides(
      String method, String pathTemplate, RiskLevel risk, boolean requiresApproval) {
    riskOverrides.put(
        key(method, pathTemplate), new RiskOverride(risk, requiresApproval));
  }

  /** 启动时自动扫描，并把结果增量并入 {@link CapabilityRegistry}。 */
  @PostConstruct
  public void scanOnStartup() {
    refresh();
    publishToCapabilityRegistry();
  }

  /**
   * 把已派生的端点能力增量注册进 {@code CapabilityRegistry}。
   *
   * <p><strong>为什么必须增量注册而不能靠构造注入</strong>：端点数量由运行期扫描 MVC 映射决定，而
   * {@code RequestMappingHandlerMapping} 只在容器 refresh 末尾可用；{@code CapabilityRegistry} 却在 refresh
   * 期间就被实例化，且构造器会把 {@code List<AgentCapability>} 的内容 copy 进内部 Map。两个时间窗没有交集，
   * 因此"在构造注入阶段让端点能力就位"在架构上不可行（实测四种写法都只能得到 14 个 SecurityTool 能力）。
   *
   * <p>这里改为在扫描完成后主动推入。护栏是在<strong>请求时</strong>查注册表，因此构造期 14 个、扫描后 182 个
   * 的过渡对治理正确性没有影响。
   *
   * <p><strong>幂等保护</strong>：{@code CapabilityRegistry.register} 在能力码重复时抛
   * {@link IllegalStateException}，因此重复调用本方法（例如测试中手工触发 {@link #refresh()}）必须被拦住。
   * {@link #published} 保证只推入一次；{@link #refresh()} 内部也只新增不重复登记，因此正常情况下不会撞码。
   */
  public int publishToCapabilityRegistry() {
    if (capabilityRegistry == null) {
      log.debug("未注入 CapabilityRegistry，跳过端点能力增量注册");
      return 0;
    }
    if (!published.compareAndSet(false, true)) {
      log.debug("端点能力已并入 CapabilityRegistry，跳过重复注册");
      return 0;
    }
    int count = 0;
    for (EndpointCapability endpoint : registry.all()) {
      // 与既有能力码冲突时跳过而非抛异常：注册表里已有同名能力说明它已被覆盖，
      // 启动不应因此失败（冲突详情在 conflicts() 中可查）。
      if (capabilityRegistry.find(endpoint.code()).isPresent()) {
        log.debug("端点能力码已存在，跳过增量注册：{}", endpoint.code());
        continue;
      }
      capabilityRegistry.register(endpoint);
      count++;
    }
    log.info(
        "端点能力已并入 CapabilityRegistry：新增 {} 个，注册表总数 {} 个（SecurityTool {} + 端点 {}）",
        count,
        capabilityRegistry.size(),
        capabilityRegistry.size() - count,
        registry.size());
    return count;
  }

  /** 是否已把端点能力并入 {@link CapabilityRegistry}。 */
  public boolean isPublishedToCapabilityRegistry() {
    return published.get();
  }

  /**
   * 重新扫描全部端点并重建注册表内容。
   *
   * <p>本方法<strong>只新增</strong>端点能力，不清空已有条目：热重载场景下清空会导致运行中的 {@code invoke_endpoint}
   * 短时失去反向映射（fail-closed 拒绝合法调用）。新映射会在下一次调用时被匹配到。
   *
   * @return 本次新登记的能力数量
   */
  public int refresh() {
    RequestMappingHandlerMapping handlerMapping = handlerMappingProvider.getIfAvailable();
    if (handlerMapping == null) {
      log.warn("未找到 RequestMappingHandlerMapping，端点能力派生跳过（invoke_endpoint 将拒绝全部端点）");
      scanned.set(true);
      return 0;
    }
    Map<RequestMappingInfo, HandlerMethod> handlerMethods = handlerMapping.getHandlerMethods();
    // 排序保证能力登记顺序稳定（Map 迭代顺序在不同 JVM 运行间可能不同），便于测试与审计对比。
    List<Map.Entry<RequestMappingInfo, HandlerMethod>> entries =
        new ArrayList<>(handlerMethods.entrySet());
    entries.sort(
        Comparator.comparing(
                (Map.Entry<RequestMappingInfo, HandlerMethod> entry) -> describeInfo(entry.getKey()))
            .thenComparing(entry -> entry.getValue().toString()));

    int added = 0;
    int seen = 0;
    for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : entries) {
      seen++;
      added += registerInfo(entry.getKey(), entry.getValue());
    }
    scanned.set(true);
    log.info(
        "端点能力派生完成：映射 {} 条，登记端点能力 {} 个，跳过 {} 条，能力码冲突 {} 个",
        seen,
        byCode.size(),
        skipped.size(),
        conflicts.size());
    if (!skipped.isEmpty()) {
      skipped.forEach((info, reason) -> log.debug("端点派生跳过 {}：{}", info, reason));
    }
    conflicts.forEach(
        (code, dropped) -> log.warn("端点能力码冲突，保留首个登记项，丢弃 {}：{}", code, dropped));
    return added;
  }

  /** 是否已完成至少一次扫描。 */
  public boolean isScanned() {
    return scanned.get();
  }

  /** 派生出的全部端点能力（按能力码排序）。 */
  public List<AgentCapability> capabilities() {
    return List.copyOf(byCode.values());
  }

  /** 派生出的端点能力数量。 */
  public int capabilityCount() {
    return byCode.size();
  }

  /** 扫描器读取到的 MVC 映射条数（含被跳过的）。 */
  public int handlerMethodCount() {
    RequestMappingHandlerMapping handlerMapping = handlerMappingProvider.getIfAvailable();
    return handlerMapping == null ? 0 : handlerMapping.getHandlerMethods().size();
  }

  /** 被跳过的映射及原因（只读快照）。 */
  public Map<String, String> skipped() {
    return Map.copyOf(skipped);
  }

  /** 能力码冲突记录（只读快照）。 */
  public Map<String, List<String>> conflicts() {
    Map<String, List<String>> snapshot = new TreeMap<>();
    conflicts.forEach((code, dropped) -> snapshot.put(code, List.copyOf(dropped)));
    return Map.copyOf(snapshot);
  }

  /** 本次扫描得到的端点注册表。 */
  public EndpointRegistry registry() {
    return registry;
  }

  // ---------------------------------------------------------------- 派生逻辑

  private int registerInfo(RequestMappingInfo info, HandlerMethod handler) {
    Set<String> paths = pathsOf(info);
    if (paths.isEmpty()) {
      skipped.put(describeInfo(info), "无路径模式");
      return 0;
    }
    Set<String> methods = methodsOf(info);
    if (methods.isEmpty()) {
      // 未限定方法（@RequestMapping 无 method 属性）意味着任意方法都可命中。
      // 保守做法是分别登记常见写方法，否则会出现"GET 被登记为只读、实际 POST 也能打进来"的漏判。
      methods = Set.of("GET", "POST", "PUT", "PATCH", "DELETE");
    }
    String description = describeHandler(handler);
    int added = 0;
    for (String path : paths) {
      for (String method : methods) {
        if (registerEndpoint(method, path, description)) {
          added++;
        }
      }
    }
    return added;
  }

  private boolean registerEndpoint(String method, String path, String handlerDescription) {
    String code = EndpointCapability.codeOf(method, path);
    EndpointCapability existing = byCode.get(code);
    if (existing != null) {
      if (existing.method().equals(RiskInference.normalizeMethod(method))
          && existing.pathTemplate().equals(path)) {
        // 完全相同的 (method, path)：多路径映射到同一模板，属于重复，静默忽略。
        return false;
      }
      conflicts
          .computeIfAbsent(code, ignored -> new ArrayList<>())
          .add(RiskInference.normalizeMethod(method) + " " + path);
      return false;
    }
    EndpointCapability capability = EndpointCapability.derive(method, path, handlerDescription);
    RiskOverride override = riskOverrides.get(key(method, path));
    if (override != null) {
      capability = capability.withRisk(override.risk(), override.requiresApproval());
    }
    if (!PathNormalizer.isValid(capability.pathTemplate())) {
      skipped.put(RiskInference.normalizeMethod(method) + " " + path, "路径模板未通过规范化校验");
      return false;
    }
    try {
      registry.register(capability);
    } catch (IllegalStateException error) {
      // 注册表已存在同 (method, path)：说明上一次扫描已经登记过，属于幂等重扫，正常。
      log.debug("端点已登记，跳过重复注册：{}", error.getMessage());
      byCode.putIfAbsent(code, capability);
      return false;
    }
    byCode.put(code, capability);
    return true;
  }

  /** 提取路径模式；Spring 6 优先使用解析后的 {@link PathPatternsRequestCondition}。 */
  static Set<String> pathsOf(RequestMappingInfo info) {
    Set<String> paths = new LinkedHashSet<>();
    PathPatternsRequestCondition pathPatterns = info.getPathPatternsCondition();
    if (pathPatterns != null) {
      pathPatterns.getPatterns().forEach(pattern -> paths.add(pattern.getPatternString()));
    }
    if (paths.isEmpty()) {
      PatternsRequestCondition patterns = info.getPatternsCondition();
      if (patterns != null) {
        paths.addAll(patterns.getPatterns());
      }
    }
    return paths;
  }

  /** 提取限定的 HTTP 方法；{@code null} 表示未限定。 */
  static Set<String> methodsOf(RequestMappingInfo info) {
    RequestMethodsRequestCondition condition = info.getMethodsCondition();
    if (condition == null) {
      return Set.of();
    }
    Set<String> methods = new LinkedHashSet<>();
    for (RequestMethod requestMethod : condition.getMethods()) {
      methods.add(requestMethod.name());
    }
    return methods;
  }

  /** 处理器方法的人类可读描述：类名 + 方法名 + 方法上的注解说明（取 Javadoc 不可行，故取注解与签名）。 */
  static String describeHandler(HandlerMethod handler) {
    Method method = handler.getMethod();
    Class<?> beanType = handler.getBeanType();
    StringBuilder builder = new StringBuilder();
    builder.append(beanType.getSimpleName()).append('#').append(method.getName()).append("()");
    RequestMapping mapping =
        AnnotatedElementUtils.findMergedAnnotation(method, RequestMapping.class);
    if (mapping != null) {
      builder.append("，注解: ").append(describeMapping(mapping));
    }
    return builder.toString();
  }

  private static String describeMapping(RequestMapping mapping) {
    StringBuilder builder = new StringBuilder();
    String[] values = mapping.value().length > 0 ? mapping.value() : mapping.path();
    builder.append('[').append(String.join(",", values)).append(']');
    if (mapping.method().length > 0) {
      List<String> methods = new ArrayList<>();
      for (RequestMethod requestMethod : mapping.method()) {
        methods.add(requestMethod.name());
      }
      builder.append(' ').append(String.join("|", methods));
    }
    return builder.toString();
  }

  private static String describeInfo(RequestMappingInfo info) {
    return pathsOf(info) + " " + methodsOf(info);
  }

  private static String key(String method, String pathTemplate) {
    return RiskInference.normalizeMethod(method) + " " + pathTemplate;
  }

  /** 人工校准项。 */
  public record RiskOverride(RiskLevel risk, boolean requiresApproval) {}

  /**
   * 端点能力层的 Spring 装配。
   *
   * <p><strong>刻意不定义 {@code CapabilityRegistry} Bean</strong>：{@code
   * AgentCapabilityAutoConfiguration#capabilityRegistry} 标了 {@code @ConditionalOnMissingBean}，若在此定义同名 Bean
   * 会与 task-1 的默认实现<strong>Bean 定义重名</strong>。Spring Boot 2.1+ 默认
   * {@code spring.main.allow-bean-definition-overriding=false}，结果是启动直接抛
   * {@code BeanDefinitionOverrideException}；即使开启覆盖，task-1 的 {@code SecurityTool} 能力也会从注册表消失，
   * 护栏会把它们误判为"未知能力"。
   *
   * <h2>端点能力如何进入 CapabilityRegistry（实测结论与最终方案）</h2>
   *
   * <p>task-1 的 {@code CapabilityRegistry} 构造器签名是 {@code (List<AgentCapability>, Set<String>)}。
   * 本任务把各种"把端点能力塞进这个 List"的写法都实测了一遍，结果如下：
   *
   * <table border="1">
   *   <caption>装配方式与 {@code CapabilityRegistry.size()} 实测值（基线 14 个 SecurityTool 能力）</caption>
   *   <tr><th>装配方式</th><th>结果</th></tr>
   *   <tr><td>{@code @Bean EndpointRegistry endpointRegistry()}（具体类型）</td><td>14（端点能力全丢）</td></tr>
   *   <tr><td>{@code @Bean @Lazy List<AgentCapability> f(scanner)}</td><td>14（延迟代理构造期求值为空）</td></tr>
   *   <tr><td>{@code @Bean List<AgentCapability> f()} 返回注册表实例</td><td>14（集合 Bean 不参与汇总）</td></tr>
   *   <tr><td>{@code EndpointRegistry extends AbstractList} + 集合类型 Bean</td><td>14（同上）</td></tr>
   *   <tr><td>用 {@code BeanDefinitionRegistryPostProcessor} 逐个注册独立 Bean</td>
   *       <td>0（该阶段 {@code RequestMappingHandlerMapping} 尚未就绪）</td></tr>
   * </table>
   *
   * <p><b>结论 1</b>：Spring 对 {@code List<T>} 的构造注入<strong>只汇总类型为 {@code T} 的独立 Bean</strong>，
   * <strong>不会</strong>把"返回类型为 {@code List<T>} 的集合 Bean"展开合并。诊断证据：容器内存在两个 {@code List}
   * Bean（各含完整 168 个元素），{@code CapabilityRegistry} 却仍只有 14 个——它完全没看到这两个集合。
   *
   * <p><b>结论 2（决定性）</b>：存在一个<strong>无法调和的时序矛盾</strong>——
   *
   * <ul>
   *   <li>端点数量由运行期扫描 {@code RequestMappingHandlerMapping} 决定，而 MVC 映射只在容器 refresh
   *       <strong>末尾</strong>才可用；
   *   <li>{@code CapabilityRegistry} 却在 refresh <strong>期间</strong>就被实例化（构造器还会把列表内容 copy 进内部
   *       Map）。
   * </ul>
   *
   * <p>因此"在构造注入阶段就让端点能力就位"在架构上<strong>不可行</strong>：任何早于 refresh 末尾的注册时机都扫不到
   * MVC 映射，而能扫到的时候注册表已经构造完毕。逐个注册独立 Bean 的路线同样撞上这个矛盾（实测得到 0 个端点）。
   *
   * <h2>最终方案：扫描后增量注册</h2>
   *
   * <p>改为<strong>不依赖构造注入</strong>：{@link EndpointCapabilityScanner} 在 {@code @PostConstruct} 中完成扫描后，
   * 直接调用 {@code CapabilityRegistry#register(AgentCapability)} 把端点能力<strong>增量推入</strong>共享的单例注册表。
   *
   * <p>这条路可行的原因是 {@code register} 已经是 {@code public final}，无需修改 {@code ai/capability/**} 的任何代码。
   * 时序上：构造期注册表有 14 个能力，扫描结束后变成 182 个——<strong>这对护栏完全够用</strong>，因为护栏是在
   * <strong>请求时</strong>查注册表，而不是在构造时。而 {@code invoke_endpoint} 持有的 {@link EndpointRegistry}
   * 引用同样是实时视图，两侧数据始终一致。
   *
   * <p>本配置因此只做两件事：暴露端点注册表，以及装配 {@code invoke_endpoint} 原语。
   */
  @Configuration(proxyBeanMethods = false)
  public static class EndpointCapabilityConfiguration {

    /**
     * 端点注册表 Bean。
     *
     * <p>供 {@code invoke_endpoint} 反向映射与扫描器共用同一个实例。它的构造不依赖任何 Bean，
     * 因此不会形成 {@code CapabilityRegistry → … → RequestMappingHandlerMapping} 的循环依赖。
     */
    @Bean
    public EndpointRegistry endpointRegistry() {
      return new EndpointRegistry();
    }

    /**
     * {@code invoke_endpoint} 通用端点原语（§4.2 路线 C）。
     *
     * <p>不能以 {@code CapabilityRegistry} 为返回类型——那样会顶掉 task-1 的默认注册表。它也不是
     * {@code CapabilityRegistry} 的构造参数，不会形成循环依赖。
     */
    @Bean
    public InvokeEndpointCapability invokeEndpointCapability(
        EndpointRegistry endpointRegistry, CapabilityRegistry capabilityRegistry) {
      return new InvokeEndpointCapability(endpointRegistry, capabilityRegistry);
    }
  }
}
