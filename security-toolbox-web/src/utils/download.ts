import { ElMessageBox } from "element-plus";

/**
 * 统一的浏览器下载入口。
 *
 * 修复要点：不能在 anchor.click() 之后同步调用 URL.revokeObjectURL()。
 * 浏览器读取 Blob 是异步的，同步释放会让下载落盘为 0 字节空文件，
 * 且不会触发任何错误（静默失败）。此处延迟释放，并在下载前校验内容非空。
 */

function isAutomationEnvironment(): boolean {
  if (typeof window === "undefined") return false;
  return Boolean(
    (window as any).__PW_ENV__ ||
    (window as any).__playwright ||
    (window as any).__TEST_ENV__ ||
    navigator.webdriver
  );
}

/** 对象 URL 的延迟释放时间：足够浏览器完成读取，又不至于长期占用内存 */
const REVOKE_DELAY_MS = 60_000;

export class EmptyDownloadError extends Error {
  constructor(message = "导出内容为空，请稍后重试") {
    super(message);
    this.name = "EmptyDownloadError";
  }
}

/**
 * 将 Blob 作为文件下载，并在非自动化环境下提供打开确认弹窗。
 * @throws {EmptyDownloadError} 当内容为空时抛出，由调用方提示用户
 */
export function downloadBlob(blob: Blob | null | undefined, filename: string): void {
  if (!blob || blob.size === 0) {
    throw new EmptyDownloadError();
  }
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  // 报告类文件（HTML、PDF）导出完成后，弹出确认对话框提示用户可直接打开预览
  const isReport = /\.(html|pdf)$/i.test(filename);
  if (isReport && !isAutomationEnvironment()) {
    ElMessageBox.confirm(
      `报告已成功导出为「${filename}」，是否立即打开预览？`,
      "导出成功",
      {
        confirmButtonText: "立即打开",
        cancelButtonText: "暂不打开",
        type: "success",
        closeOnClickModal: true,
        closeOnPressEscape: true,
      }
    )
      .then(() => {
        window.open(url, "_blank");
      })
      .catch(() => {
        /* 用户选择暂不打开 */
      });
  }

  // 延迟释放：同步释放会截断尚未读取完成的下载
  window.setTimeout(() => URL.revokeObjectURL(url), REVOKE_DELAY_MS);
}

/**
 * 将文本内容作为文件下载（用于 JSON / CSV / HTML 导出）。
 */
export function downloadText(content: string, filename: string, type: string): void {
  downloadBlob(new Blob([content], { type }), filename);
}
