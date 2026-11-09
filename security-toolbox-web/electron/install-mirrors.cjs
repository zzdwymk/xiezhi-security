// Populate Electron / electron-builder binary mirrors as environment variables for the
// current process (and children spawned by npm's install lifecycle).
// Kept as a requireable hook so package.json "preinstall" stays a one-liner.
const MIRRORS = {
  ELECTRON_MIRROR: "https://npmmirror.com/mirrors/electron/",
  ELECTRON_BUILDER_BINARIES_MIRROR: "https://npmmirror.com/mirrors/electron-builder-binaries/",
};

function applyInstallMirrors(options = {}) {
  const disabled = /^(1|true|yes)$/i.test(String(options.disabled ?? process.env.TOOLBOX_NO_MIRROR ?? ""));
  if (disabled) return { applied: false, reason: "TOOLBOX_NO_MIRROR" };
  const applied = {};
  for (const [key, value] of Object.entries(MIRRORS)) {
    if (!process.env[key]) process.env[key] = value;
    applied[key] = process.env[key];
  }
  return { applied: true, mirrors: applied };
}

module.exports = { MIRRORS, applyInstallMirrors };
