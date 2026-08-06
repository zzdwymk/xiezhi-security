export function formatDateTime(value?: string | null) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime()))
    return String(value)
      .replace("T", " ")
      .replace(/\.\d+Z?$/, "")
      .replace(/Z$/, "");
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  })
    .format(date)
    .replace(/\//g, "-");
}

/**
 * Make persisted task log lines readable without changing the raw command/output text.
 * The server historically stored an ISO timestamp at the beginning of each line, so
 * this formatter accepts both the old ISO form and the already formatted display form.
 */
export function formatExecutionLog(value?: string | null) {
  if (!value) return "";
  return String(value)
    .split(/\r?\n/)
    .map((line) => {
      const match = line.match(
        /^(\d{4}-\d{2}-\d{2}T[^\s]+|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s{2}(.*)$/,
      );
      if (!match) return line;
      const timestamp = formatDateTime(match[1]);
      return timestamp ? `${timestamp}  ${match[2]}` : line;
    })
    .join("\n");
}
