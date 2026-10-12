package com.bachelor.toolbox.ai.guard;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 按需授权的<strong>用户交互入口</strong>（"先看见，要用时申请"的批准环节）。
 *
 * <h2>为什么需要这个 Controller</h2>
 *
 * <p>护栏的第三个出口（{@link CapabilityOutcome#approvalRequired}）只是"请求授权"，
 * 真正让链路可用还需要一个<strong>用户能点击"同意"的地方</strong>。没有它，
 * 护栏返回申请后没人能批准，Agent 依然用不了那些能力——机制存在但不可用。
 *
 * <h2>三个端点</h2>
 *
 * <table border="1">
 *   <caption>按需授权 API</caption>
 *   <tr><th>方法</th><th>路径</th><th>作用</th></tr>
 *   <tr>
 *     <td>GET</td><td>{@code /api/ai/guard/approvals/pending}</td>
 *     <td>列出待批申请（供 UI 渲染确认卡片）</td>
 *   </tr>
 *   <tr>
 *     <td>POST</td><td>{@code /api/ai/guard/approvals/grant}</td>
 *     <td>用户批准 → 签发凭据</td>
 *   </tr>
 *   <tr>
 *     <td>DELETE</td><td>{@code /api/ai/guard/approvals}</td>
 *     <td>撤销凭据（用户撤回授权）</td>
 *   </tr>
 * </table>
 *
 * <h2>⚠️ 安全约束</h2>
 *
 * <ol>
 *   <li><strong>申请卡片内容由平台生成</strong>：{@link CapabilityApprovalRequest#humanReadableSummary()}
 *       来自能力元数据与参数原文，<strong>不含 Agent 措辞</strong>。若允许 Agent 自定义文案，
 *       它可以"把 3306 端口说成 80"来说服用户批准。
 *   <li><strong>Agent 不得调用批准端点</strong>：本 Controller 是用户界面的一部分。
 *       若 Agent 能自行调用，等于"自己批准自己"，机制完全失效。
 *       <strong>部署时必须确保 AI Agent 的调用凭据无法访问 {@code /api/ai/guard/approvals/**}</strong>。
 *   <li><strong>不提供"全部允许"</strong>：批准必须逐条、绑定具体四要素。
 *       刻意不实现"以后都同意"这类批量放行（那是 ARTEX 的 {@code fail_action: allow} 式失效）。
 * </ol>
 */
@RestController
@RequestMapping("/api/ai/guard/approvals")
public class CapabilityApprovalController {

  private static final Logger log = LoggerFactory.getLogger(CapabilityApprovalController.class);

  private final CapabilityApprovalGrantResolver grantResolver;
  private final PendingApprovalRegistry pendingRegistry;

  public CapabilityApprovalController(
      CapabilityApprovalGrantResolver grantResolver, PendingApprovalRegistry pendingRegistry) {
    this.grantResolver = grantResolver;
    this.pendingRegistry = pendingRegistry;
  }

  /**
   * 列出待批申请。
   *
   * <p>UI 据此渲染确认卡片。卡片内容<strong>全部来自平台生成的字段</strong>，
   * 不包含 Agent 提供的自由文本。
   */
  @GetMapping("/pending")
  public List<Map<String, Object>> pending() {
    return pendingRegistry.pending().stream()
        .map(CapabilityApprovalController::describe)
        .toList();
  }

  /**
   * 用户批准 → 签发凭据。
   *
   * <p>请求体须携带与申请完全一致的四要素（能力 + 目标 + 参数摘要），
   * 服务端据此<strong>重新生成</strong>凭据——而不是信任客户端传来的凭据对象。
   */
  @PostMapping("/grant")
  public ResponseEntity<Map<String, Object>> grant(@RequestBody GrantRequest request) {
    if (request == null || request.capabilityCode() == null || request.parameterDigest() == null) {
      return ResponseEntity.badRequest().body(Map.of("error", "缺少能力码或参数摘要"));
    }
    CapabilityApprovalRequest approvalRequest =
        pendingRegistry
            .find(request.capabilityCode(), request.targetId(), request.parameterDigest())
            .orElse(null);
    if (approvalRequest == null) {
      // 没有对应的待批申请 → 拒绝。
      // 这防的是"凭空构造批准"：用户只能批准 Agent 真实提出过的申请。
      return ResponseEntity.badRequest()
          .body(Map.of("error", "找不到对应的待批申请，拒绝签发凭据（防止凭空批准）"));
    }
    ApprovalLevel level = request.level() == null ? ApprovalLevel.SINGLE : request.level();
    if (level == ApprovalLevel.FORBIDDEN) {
      return ResponseEntity.badRequest().body(Map.of("error", "禁止的能力不能签发凭据"));
    }
    CapabilityApprovalGrant grant = grantResolver.grant(approvalRequest, level);
    pendingRegistry.remove(request.capabilityCode(), request.targetId(), request.parameterDigest());
    log.info(
        "用户批准能力调用: capability={} target={} level={}",
        grant.capabilityCode(),
        grant.targetId(),
        grant.level());
    return ResponseEntity.ok(describe(grant));
  }

  /** 撤销凭据（用户撤回授权）。 */
  @DeleteMapping
  public ResponseEntity<Map<String, Object>> revoke(@RequestBody GrantRequest request) {
    if (request == null || request.capabilityCode() == null) {
      return ResponseEntity.badRequest().body(Map.of("error", "缺少能力码"));
    }
    boolean removed =
        grantResolver instanceof InMemoryCapabilityApprovalGrantResolver inMemory
            ? inMemory.revoke(request.capabilityCode(), request.targetId(), request.parameterDigest())
            : false;
    return ResponseEntity.ok(Map.of("revoked", removed));
  }

  // ------------------------------------------------------------------ 视图

  private static Map<String, Object> describe(CapabilityApprovalRequest request) {
    Map<String, Object> view = new LinkedHashMap<>();
    view.put("capabilityCode", request.capabilityCode());
    view.put("targetId", request.targetId());
    view.put("parameterDigest", request.parameterDigest());
    view.put("risk", request.risk());
    view.put("requestedLevel", String.valueOf(request.requestedLevel()));
    // 平台生成的摘要：不含 Agent 措辞。
    view.put("summary", request.humanReadableSummary());
    view.put("parameters", request.parameters());
    return view;
  }

  private static Map<String, Object> describe(CapabilityApprovalGrant grant) {
    Map<String, Object> view = new LinkedHashMap<>();
    view.put("capabilityCode", grant.capabilityCode());
    view.put("targetId", grant.targetId());
    view.put("parameterDigest", grant.parameterDigest());
    view.put("level", String.valueOf(grant.level()));
    view.put("grantedAt", String.valueOf(grant.grantedAt()));
    view.put("expiresAt", String.valueOf(grant.expiresAt()));
    return view;
  }

  /**
   * 批准请求体。
   *
   * <p>四要素必须与申请完全一致——服务端据此定位待批申请，
   * <strong>不信任客户端传来的其他字段</strong>。
   */
  public record GrantRequest(
      String capabilityCode, String targetId, String parameterDigest, ApprovalLevel level) {}
}
