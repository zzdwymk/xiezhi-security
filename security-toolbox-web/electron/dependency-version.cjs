function parseStableVersion(value) {
  const normalized = String(value || "")
    .trim()
    .replace(/^v/i, "");
  if (!/^\d+\.\d+\.\d+$/.test(normalized)) return undefined;
  const parts = normalized.split(".").map(Number);
  if (parts.some((part) => !Number.isSafeInteger(part))) return undefined;
  return { normalized, parts };
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
