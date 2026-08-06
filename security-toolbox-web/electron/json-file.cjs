const fs = require("fs");
const path = require("path");

function readJsonFile(candidate, fallback = {}) {
  try {
    return JSON.parse(fs.readFileSync(candidate, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJsonFileAtomic(candidate, value) {
  fs.mkdirSync(path.dirname(candidate), { recursive: true });
  const temporary = `${candidate}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
  fs.renameSync(temporary, candidate);
}

module.exports = { readJsonFile, writeJsonFileAtomic };
