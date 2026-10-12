package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.traffic.TrafficReplayService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code replay_request} —— 重放一条已捕获的 HTTP 请求（设计文档 §4.2 路线 A）。
 *
 * <h2>目标绑定：{@link BindingMode#RESOLVED}</h2>
 *
 * <p>重放会<strong>真的向目标发一个包</strong>（{@link TrafficReplayService#replay} 建立真实 TCP/TLS 连接），是本包中
 * "触及目标"最字面的一条能力。{@code targetId} 必填且必须通过 L-A 的范围、端口、有效期校验；服务层还会额外核对
 * "发包 URL 主机与授权目标一致"（{@code TrafficReplayService} 的既有逻辑），两层校验互补：
 *
 * <ul>
 *   <li>护栏 L-A 保证"这个目标是被授权的"；
 *   <li>服务层保证"这个 URL 确实打在该目标上"（防 Agent 用授权目标 A 的 ID 去请求主机 B）。
 * </ul>
 *
 * <p>等级 {@link RiskLevel#DESTRUCTIVE} 且 {@code requiresApproval = true}：重放可能触发目标侧的状态变更（幂等性无法保证，
 * 例如重放一个 {@code DELETE} 或转账请求），属于 §6.6 中"不可逆"一档。注意 {@code DESTRUCTIVE} 会让护栏 L-B 要求该能力
 * 出现在显式白名单（{@code toolbox.agent.guard.whitelist}）中——这是刻意的：重放是最容易被滥用为攻击流量的能力，
 * 默认关闭、显式开启。
 */
@Component
public class ReplayRequestCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "replay_request";

  /** 允许的重放方法（与 {@code TrafficReplayService} 的 METHOD 模式一致，这里是业务白名单）。 */
  private static final List<String> ALLOWED_METHODS =
      List.of("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE");

  private final TrafficReplayService replay;

  public ReplayRequestCapability(TrafficReplayService replay) {
    super(
        CODE,
        "重放请求",
        "重放一条已捕获的 HTTP 请求到授权目标，返回响应状态、响应头与响应体摘要。"
            + "参数：packetId（作为重放模板的报文 ID）、targetId（授权目标 ID，必填）、"
            + "url（要请求的 URL，主机必须与授权目标一致）、method（HTTP 方法）、"
            + "headers（请求头文本，可选，每行 'Name: value'，上限 64 KB）、"
            + "body（请求体字符串，可选，上限 1 MB）。"
            + "本能力会向目标真实发包，可能产生不可逆的副作用（例如重放一个删除类请求），"
            + "因此属高危能力：需要人工确认，且必须在 toolbox.agent.guard.whitelist 中显式开启后才可由 Agent 调用。",
        CapabilityKind.EXECUTE,
        RiskLevel.DESTRUCTIVE,
        true,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.replay = replay;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("packetId", integerProperty(1, "作为重放模板的已捕获报文 ID"));
    properties.put("targetId", integerProperty(1, "授权目标 ID；发包 URL 的主机必须与该目标一致"));
    properties.put("url", property("string", "要请求的完整 URL，主机必须与授权目标一致"));
    properties.put("method", enumProperty(ALLOWED_METHODS, "HTTP 方法"));
    properties.put("headers", property("string", "可选：请求头文本，每行形如 'Name: value'，上限 64 KB"));
    properties.put("body", property("string", "可选：请求体，上限 1 MB"));
    return objectSchema(properties, List.of("packetId", "targetId", "url", "method"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "packetId");
    requirePositiveLong(params, "targetId");
    String url = requireText(params, "url");
    String method = requireText(params, "method").toUpperCase(java.util.Locale.ROOT);
    if (!ALLOWED_METHODS.contains(method)) {
      throw new com.bachelor.toolbox.common.ApiException("不支持的 HTTP 方法: " + method);
    }
    String headers = optionalText(params, "headers");
    if (headers != null && headers.length() > 64 * 1024) {
      throw new com.bachelor.toolbox.common.ApiException("重放请求头不能超过 64 KB");
    }
    Object body = params.get("body");
    if (body != null && body.toString().length() > 1024 * 1024) {
      throw new com.bachelor.toolbox.common.ApiException("重放请求体不能超过 1 MB");
    }
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      throw new com.bachelor.toolbox.common.ApiException("重放 URL 必须以 http:// 或 https:// 开头");
    }
  }

  /** 执行重放。 */
  public TrafficReplayService.ReplayResponse replay(
      Long packetId, Long targetId, String url, String method, String headers, String body) {
    return replay.replay(
        packetId, new TrafficReplayService.ReplayRequest(targetId, method, url, headers, body));
  }
}
