import { toErrorMessage } from "./errorMessage";

interface ScanResultLike {
  status?: string;
  message?: string;
  engine?: string;
}

export function scanErrorDetail(error: unknown): string {
  if (typeof error === "string") return error.trim();
  if (!error || typeof error !== "object") return "";
  const value = error as { message?: string; response?: { data?: { message?: string } | string } };
  const data = value.response?.data;
  return String((typeof data === "string" ? data : data?.message) || value.message || "").trim();
}

/** Keep the failed step and the next action readable; retain diagnostics separately. */
export function targetedScanPresentation(result: ScanResultLike) {
  const raw = result.message?.trim() || "";
  const engine = /zap/i.test(result.engine || "") ? "ZAP" : /xray/i.test(result.engine || "") ? "Xray" : /sqlmap/i.test(result.engine || "") ? "sqlmap" : "本地";
  let title = raw;
  let guidance = "";
  if (result.status === "RUNNING" || result.status === "COMPLETED") {
    return { title, guidance, detail: "" };
  }
  if (result.status === "CANCELLED") {
    title = "检测已取消，尚未完成";
    guidance = "本次没有完整的检测结论；需要继续检查时，请重新测试。";
  } else if (result.status === "TIMEOUT") {
    title = "检测已超时，尚未完成";
    guidance = "请确认目标网站能正常打开，稍后重新测试；若反复超时，请检查目标响应速度和检测工具状态。";
    if (/超时|等待上限|等待.*(?:超过|已达)/.test(raw) && toErrorMessage(raw, "") === raw) {
      // The service distinguishes the overall scan budget from an engine
      // response timeout. Keep its budget, last progress and next action visible.
      const adviceAt = raw.search(/请|建议|可(?:降低|调整|在|重新)/);
      title = adviceAt > 0 ? raw.slice(0, adviceAt).trim().replace(/[。；]$/, "") : raw;
      if (adviceAt > 0) guidance = raw.slice(adviceAt);
    }
  } else if (result.status !== "FAILED") {
    title = "检测状态待核实，暂时无法给出结论";
    guidance = "没有收到明确的完成状态，请查看检测记录或重新测试。";
  } else if (/[\u3400-\u9fff]/.test(raw) && /请|建议/.test(raw)
      && !/REST|INTERNAL_ERROR|\bHTTP\s*\d{3}|exception|traceback|[a-z]:\\|\/(?:home|users|usr|var|opt)\//i.test(raw)) {
    // Preserve actionable explanations supplied by the service instead of
    // replacing their specific cause or remediation with a generic guess.
    const adviceAt = raw.search(/请|建议/);
    if (adviceAt > 0) {
      title = raw.slice(0, adviceAt).trim().replace(/[。；]$/, "");
      guidance = raw.slice(adviceAt);
    }
  } else if (/登录|授权|流量记录|目标.*不存在|无权访问/.test(raw)) {
    title = toErrorMessage(raw, "无法执行本次检测");
    guidance = /登录/.test(title)
      ? "请重新登录后再测试。"
      : /流量记录/.test(title)
        ? "请重新选择一条可用的流量记录。"
        : "请检查所选授权目标与本次访问地址是否一致。";
  } else if (/core\/action\/accessUrl/i.test(raw)) {
    title = "ZAP 访问目标网站时出错，检测未完成";
    guidance = "请确认目标设备已开机、网站服务已启动，且当前电脑能打开该地址，再重新测试。若网站能正常打开，请重启 ZAP 后重试。";
  } else if (/ZAP REST|INTERNAL_ERROR|ascan\/(?:action|view)|core\/view\/alerts/i.test(raw)) {
    title = /ascan\/action\/scan/i.test(raw)
      ? "ZAP 无法启动检测"
      : /(?:status|alerts)/i.test(raw)
        ? "无法获取 ZAP 的检测结果"
        : "ZAP 检测工具出现错误，检测未完成";
    guidance = "请确认 ZAP 已正常启动后重新测试；若仍失败，可展开技术详情排查原因。";
  } else if (/certificate|SSLHandshake|TLS|证书|安全连接/i.test(raw)) {
    title = "无法与目标网站建立安全连接，检测未完成";
    guidance = "请检查目标网站的 HTTPS 配置、证书和访问地址，确认能正常访问后重新测试。";
  } else if (/connection refused|econnrefused|connection reset|no route to host|unknownhost|name or service not known|could not resolve|failed to resolve|unable to connect|无法连接目标|目标.*(?:不可达|无法访问|未响应)|连接被拒绝/i.test(raw)) {
    title = "无法连接目标网站，检测未完成";
    guidance = "请确认目标设备已开机、网站服务已启动，并检查地址、端口和网络连接，再重新测试。";
  } else if (/timeout|timed out|超时/i.test(raw)) {
    title = "等待响应超时，检测未完成";
    guidance = "请确认目标网站能正常打开，稍后重新测试；若反复超时，请检查网络和检测工具状态。";
  } else if (/空输出|没有.*(?:结果|输出)|未返回.*(?:结果|输出)|结果.*(?:无效|无法解析)|output|report.*(?:empty|missing|invalid)/i.test(raw)) {
    title = "检测工具没有返回有效结果";
    guidance = "本次无法判断目标是否存在漏洞。请检查检测工具是否正常运行，然后重新测试。";
  } else if (/流式|stream|failed to fetch|fetch failed|network error|检测.*(?:中断|连接断开)/i.test(raw)) {
    title = "检测连接中断，未收到完整结果";
    guidance = "请确认本地检测服务仍在运行，再查看检测记录或重新测试。";
  } else if (/not found|未安装|启动失败|无法启动|cannot run|createprocess|executable|exit(?:ed)? (?:code|status)|退出码|异常退出|(?:工具|可执行文件|ZAP|Xray|sqlmap).*不存在/i.test(raw)) {
    title = `${engine} 检测工具未能正常运行`;
    guidance = "请在离线工具集中检查该工具是否已安装并能正常启动，再重新测试。";
  } else {
    title = toErrorMessage(raw, `${engine} 检测未完成`);
    guidance = /登录/.test(title)
      ? "请重新登录后再测试。"
      : /授权|目标.*范围/.test(title)
        ? "请检查所选授权目标与本次访问地址是否一致。"
        : "请检查目标网站和检测工具是否正常，再重新测试。";
  }
  return { title, guidance, detail: raw && raw !== title ? raw : "" };
}
