#!/usr/bin/env node
/*
 * 安装前镜像助手：
 * Electron 与 electron-builder 的二进制下载由它们的 install 脚本读取**环境变量**，
 * 而不是 npm 的 .npmrc 键（npm 11 起会对 .npmrc 里的 electron_mirror 等未知键报警）。
 *
 * 由 package.json 的 "preinstall" 自动执行；也可手动运行：
 *   node scripts/apply-install-mirrors.cjs
 *
 * 若网络可直连官方源，设置 TOOLBOX_NO_MIRROR=1 即可关闭镜像注入。
 * 已存在的同名环境变量不会被覆盖（方便 CI 指定其他镜像）。
 */
const { applyInstallMirrors } = require("../electron/install-mirrors.cjs");

const result = applyInstallMirrors();
if (!result.applied) {
  console.log(`[install-mirrors] 已跳过镜像注入（${result.reason}）。`);
  process.exit(0);
}
for (const [key, value] of Object.entries(result.mirrors)) {
  console.log(`[install-mirrors] ${key}=${value}`);
}
// npm 的 preinstall 子进程环境会传给随后的 electron/electron-builder 下载步骤。
