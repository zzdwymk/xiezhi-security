function parseStableVersion(value) {
  const normalized = String(value || "")
    .trim()
    .replace(/^v/i, "");
  // 兼容两段主.小版本（如 PostgreSQL 的 18.6，没有补丁号），视为 X.Y.0；
  // 三段 X.Y.Z 也正常解析。
  if (!/^\d+\.\d+(?:\.\d+)?$/.test(normalized)) return undefined;
  const rawParts = normalized.split(".").map(Number);
  if (rawParts.some((part) => !Number.isSafeInteger(part))) return undefined;
  const parts = [rawParts[0], rawParts[1], rawParts[2] || 0];
  const canonical = parts.join(".");
  return { normalized: canonical, parts };
}

function compareStableVersions(left, right) {
  const leftVersion = parseStableVersion(left);
  const rightVersion = parseStableVersion(right);
  if (!leftVersion || !rightVersion) return undefined;
  for (let index = 0; index < 3; index += 1) {
    if (leftVersion.parts[index] !== rightVersion.parts[index]) {
      return leftVersion.parts[index] > rightVersion.parts[index] ? 1 : -1;
    }
  }
  return 0;
}

function evaluateInstalledRelease({
  metadata,
  repository,
  latestVersion,
  payloadExists,
}) {
  const installedVersion = parseStableVersion(metadata?.version)?.normalized;
  const normalizedLatest = parseStableVersion(latestVersion)?.normalized;
  const managed =
    Boolean(payloadExists) &&
    Boolean(installedVersion) &&
    String(metadata?.repository || "").toLowerCase() ===
      String(repository || "").toLowerCase();
  const comparison =
    managed && normalizedLatest
      ? compareStableVersions(installedVersion, normalizedLatest)
      : undefined;
  return {
    managed,
    installedVersion,
    latestVersion: normalizedLatest,
    comparison,
    upToDate: managed && typeof comparison === "number" && comparison >= 0,
    updateAvailable:
      managed && typeof comparison === "number" && comparison < 0,
  };
}

module.exports = {
  compareStableVersions,
  evaluateInstalledRelease,
  parseStableVersion,
};
