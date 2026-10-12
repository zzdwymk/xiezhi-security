package com.bachelor.toolbox.ai.capability;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * 从请求参数中解析授权目标 ID —— 护栏与能力层<strong>共用的单一实现</strong>。
 *
 * <h2>为什么必须有本类</h2>
 *
 * <p>"从参数里找出 targetId"这件事原先在两处各写一份：
 *
 * <ul>
 *   <li>{@code CapabilityGate.targetIdsOf}（护栏侧，用于 L-C' 端点参数策略）
 *   <li>{@code InvokeEndpointCapability.targetBindings}（能力侧，P1-4 修复需要它解析真实目标）
 * </ul>
 *
 * <p>若各写一份，就会出现第四份重复实现——<strong>而重复正是本次全部缺陷的根因</strong>
 * （三份工具参数校验 → D-1..D-6 漂移）。
 *
 * <h2>为什么放在 {@code ai.capability} 而不是 {@code ai.guard}</h2>
 *
 * <p>{@code ai.guard} 已经依赖 {@code ai.endpoint}（护栏读 {@code EndpointRegistry}）。
 * 若本类放 {@code ai.guard}，{@code ai.endpoint} 引用它就会形成
 * <strong>{@code ai.guard} ⇄ {@code ai.endpoint} 的包级循环</strong>。
 * {@code ai.capability} 是两者的共同下游，放这里无环。
 *
 * <h2>语义</h2>
 *
 * <ul>
 *   <li>识别键：{@code targetId}、{@code target_id}、{@code targetIds}、{@code target_ids}
 *   <li>只接受<strong>正整数</strong>；非数字/非正数一律<strong>不加入</strong>结果集
 *   <li><strong>永不抛异常</strong>——"解析不出"由调用方决定如何处理
 *       （护栏：返回哨兵 → fail-closed 拒绝）
 * </ul>
 */
public final class TargetIdExtractor {

  private TargetIdExtractor() {}

  /** 目标 ID 的识别键（含下划线变体与复数形式）。 */
  public static final String[] TARGET_ID_KEYS = {
    "targetId", "target_id", "targetIds", "target_ids"
  };

  /**
   * 从一层参数映射中解析目标 ID（只看顶层键）。
   *
   * @return 正整数 ID 集合；可能为空（调用方须 fail-closed 处理）
   */
  public static Set<String> extract(Map<String, Object> source) {
    Set<String> ids = new LinkedHashSet<>();
    if (source == null) {
      return ids;
    }
    for (String key : TARGET_ID_KEYS) {
      Object value = source.get(key);
      if (value == null) {
        continue;
      }
      if (value instanceof Collection<?> collection) {
        collection.forEach(item -> addId(item, ids));
      } else if (value instanceof Object[] array) {
        for (Object item : array) {
          addId(item, ids);
        }
      } else {
        addId(value, ids);
      }
    }
    return ids;
  }

  /**
   * 从多层来源解析目标 ID（依次扫描，取并集）。
   *
   * <p>护栏用它同时看 {@code body} 与 {@code params}——目标可能出现在任一层。
   */
  public static Set<String> extract(Map<String, Object> first, Map<String, Object> second) {
    Set<String> ids = new LinkedHashSet<>(extract(first));
    ids.addAll(extract(second));
    return ids;
  }

  /**
   * <strong>深度解析</strong>：在任意嵌套层级查找目标 ID。
   *
   * <p>供通用原语使用——{@code invoke_endpoint} 的 {@code body}/{@code query} 是自由 JSON，
   * 目标可能藏在任意深度（如 {@code {"parameters":{"targetId":1}}}）。
   *
   * <p>⚠️ 深度扫描比顶层扫描<strong>更容易误报</strong>（任意嵌套里的 {@code targetId} 都会被采集）。
   * 这是刻意的保守取向：<strong>多解析一个目标 = 多一次授权校验（安全）；少解析一个 = 漏一次（漏洞）</strong>。
   */
  public static Set<String> extractDeep(Object value) {
    Set<String> ids = new LinkedHashSet<>();
    collectDeep(value, ids, 0);
    return ids;
  }

  /** 深度上限：防止异常深的嵌套导致栈溢出（正常请求不会超过这个深度）。 */
  private static final int MAX_DEPTH = 16;

  private static void collectDeep(Object value, Set<String> sink, int depth) {
    if (value == null || depth > MAX_DEPTH) {
      return;
    }
    if (value instanceof Map<?, ?> map) {
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        String key = String.valueOf(entry.getKey());
        Object item = entry.getValue();
        if (isTargetIdKey(key)) {
          if (item instanceof Collection<?> collection) {
            collection.forEach(element -> addId(element, sink));
          } else if (item instanceof Object[] array) {
            for (Object element : array) {
              addId(element, sink);
            }
          } else {
            addId(item, sink);
          }
        }
        // 继续向下（即使当前键是 targetId，其值也可能是对象）。
        collectDeep(item, sink, depth + 1);
      }
      return;
    }
    if (value instanceof Collection<?> collection) {
      collection.forEach(item -> collectDeep(item, sink, depth + 1));
      return;
    }
    if (value instanceof Object[] array) {
      for (Object item : array) {
        collectDeep(item, sink, depth + 1);
      }
    }
  }

  private static boolean isTargetIdKey(String key) {
    for (String candidate : TARGET_ID_KEYS) {
      if (candidate.equals(key)) {
        return true;
      }
    }
    return false;
  }

  /** 只接受正整数；其余静默忽略（由调用方按 fail-closed 处理空结果）。 */
  private static void addId(Object value, Set<String> sink) {
    if (value == null) {
      return;
    }
    try {
      long id = Long.parseLong(String.valueOf(value).trim());
      if (id > 0) {
        sink.add(Long.toString(id));
      }
    } catch (NumberFormatException ignored) {
      // 非数字 ID：不加入结果集。调用方看到"解析不出"后应 fail-closed。
    }
  }
}
