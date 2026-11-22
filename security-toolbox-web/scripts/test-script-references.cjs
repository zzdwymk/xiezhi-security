"use strict";
// 守卫：package.json 中所有脚本引用的本地文件必须存在。
// R325/R326 的教训：测试脚本被 .gitignore 忽略后，npm 脚本在干净克隆里直接失败。
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const pattern = /(?:node|electron-builder)[^\r\n]*?((?:scripts|electron|tests|build)\/[^\s"']+\.(?:cjs|js|mjs|json|ico|png))/g;

const missing = [];
for (const [name, command] of Object.entries(pkg.scripts || {})) {
  for (const match of String(command).matchAll(pattern)) {
    const relative = match[1];
    if (!fs.existsSync(path.join(root, relative))) {
      missing.push({ script: name, file: relative });
    }
  }
}

if (missing.length) {
  console.error("以下 npm 脚本引用的文件不存在：");
  for (const item of missing) console.error(`  ${item.script} -> ${item.file}`);
  process.exit(1);
}
console.log(`脚本引用文件检查通过（${Object.keys(pkg.scripts || {}).length} 个脚本）`);
