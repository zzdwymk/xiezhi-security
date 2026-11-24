'use strict'

/**
 * 桌面凭据“变更型”操作的授权策略（第401轮）。
 *
 * 首次设置（configured=false）允许生成/初始化/绑定；一旦账号已完成首次设置，
 * 任何重置 admin 密码或重新绑定的动作都必须先通过 Windows Hello 重新验证，
 * 不能仅凭“来自可信渲染进程”就执行。
 */
function credentialMutationPolicy({configured = false, helloVerified = false} = {}) {
  if (!configured) return {allowed: true, mode: 'first-time'}
  if (helloVerified === true) return {allowed: true, mode: 'reauthenticated'}
  return {
    allowed: false,
    mode: 'reauthentication-required',
    code: 'credential_reauthentication_required',
  }
}

module.exports = {credentialMutationPolicy}
