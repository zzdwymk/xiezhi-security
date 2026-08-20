export const HEX_VIEW_BYTES_PER_ROW = 16;
export const HEX_VIEW_DEFAULT_PAGE_SIZE = 512;

export interface HexViewRow {
  offset: number;
  offsetLabel: string;
  hexCells: string[];
  ascii: string;
}

export function clampHexOffset(
  requestedOffset: number,
  fileSize: number,
  pageSize = HEX_VIEW_DEFAULT_PAGE_SIZE,
) {
  const safeFileSize = Math.max(0, Math.trunc(fileSize));
  const safePageSize = Math.max(1, Math.trunc(pageSize));
  const maxOffset = Math.max(0, safeFileSize - safePageSize);
  if (!Number.isFinite(requestedOffset)) return 0;
  return Math.min(Math.max(0, Math.trunc(requestedOffset)), maxOffset);
}

export function parseHexOffset(value: string) {
  const input = value.trim().replace(/_/g, "");
  if (!input) throw new Error("请输入偏移量");
  const isHex = /^0x[0-9a-f]+$/i.test(input);
  const isDecimal = /^\d+$/.test(input);
  if (!isHex && !isDecimal) {
    throw new Error("偏移量请使用十进制或 0x 开头的十六进制");
  }
  const offset = Number.parseInt(input, isHex ? 16 : 10);
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new Error("偏移量超出可用范围");
  }
  return offset;
}

export function formatHexOffset(offset: number, fileSize = 0) {
  const safeOffset = Math.max(0, Math.trunc(offset));
  const largest = Math.max(safeOffset, Math.max(0, Math.trunc(fileSize) - 1));
  const width = Math.max(8, largest.toString(16).length);
  return safeOffset.toString(16).toUpperCase().padStart(width, "0");
}

export function byteToPrintableAscii(byte: number) {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
}

export function buildHexRows(
  bytes: Uint8Array,
  baseOffset = 0,
  fileSize = baseOffset + bytes.length,
  bytesPerRow = HEX_VIEW_BYTES_PER_ROW,
): HexViewRow[] {
  const rowSize = Math.max(1, Math.trunc(bytesPerRow));
  const rows: HexViewRow[] = [];
  for (let index = 0; index < bytes.length; index += rowSize) {
    const slice = bytes.subarray(index, index + rowSize);
    const hexCells = Array.from(slice, (byte) =>
      byte.toString(16).toUpperCase().padStart(2, "0"),
    );
    while (hexCells.length < rowSize) hexCells.push("");
    rows.push({
      offset: baseOffset + index,
      offsetLabel: formatHexOffset(baseOffset + index, fileSize),
      hexCells,
      ascii: Array.from(slice, byteToPrintableAscii).join(""),
    });
  }
  return rows;
}
