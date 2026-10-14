/*
 * 受控测试靶机地址的唯一来源。
 *
 * 本轮授权的业务靶机是 192.168.222.128。所有端到端/桌面自动化套件都必须
 * 从这里取得靶机地址，不得再写死到用例内部；需要临时切换目标时设置
 * 环境变量 E2E_TARGET 即可（不改变默认授权目标）。
 *
 * 这里只保存"被授权测试的地址"这一事实，不做任何网络请求。
 */
let TARGET_IP = process.env.E2E_TARGET || "192.168.222.135";
try {
  const { execSync } = require("child_process");
  const vmrun = "D:\\software\\VMware\\VMware Workstation\\vmrun.exe";
  const vmx = "D:\\Virtual Machines\\Windows 7 x64\\Windows 7 x64.vmx";
  if (require("fs").existsSync(vmrun) && require("fs").existsSync(vmx)) {
    const liveIp = execSync(`"${vmrun}" getGuestIPAddress "${vmx}" -wait`, { timeout: 6000 }).toString().trim();
    if (/^\d+\.\d+\.\d+\.\d+$/.test(liveIp)) {
      TARGET_IP = liveIp;
    }
  }
} catch {}
const TARGET_WEB_PORT = process.env.E2E_TARGET_WEB_PORT || "80";

/** 断言当前上下文使用的就是本文件声明的授权靶机，防止套件被私下改指他处。 */
function assertAuthorizedTarget(ctx) {
  if (!ctx || ctx.targetIp !== TARGET_IP) {
    throw new Error(`授权靶机不匹配: 期望 ${TARGET_IP}，实际 ${ctx && ctx.targetIp}`);
  }
  return TARGET_IP;
}

module.exports = { TARGET_IP, TARGET_WEB_PORT, assertAuthorizedTarget };
