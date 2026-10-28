// Dump the packaged Findings page CSS out of app.asar so we can see exactly which
// filter-toolbar layout is running inside the desktop app.
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const asarPath = path.join(root, 'desktop-release', 'win-unpacked', 'resources', 'app.asar');
const buf = fs.readFileSync(asarPath);
const headerSize = buf.readUInt32LE(12);
const headerJson = buf.subarray(16, 16 + headerSize).toString('utf8');
const header = JSON.parse(headerJson);

const files = [];
const walk = (node, prefix) => {
  for (const [name, value] of Object.entries(node.files || {})) {
    const next = `${prefix}/${name}`;
    if (value.files) walk(value, next);
    else files.push({ path: next, offset: Number(value.offset), size: value.size });
  }
};
walk(header, '');

const findingsCss = files.filter((f) => /Findings-[A-Za-z0-9_-]+\.css$/.test(f.path));
console.log('packaged Findings CSS:', findingsCss.map((f) => f.path).join(', ') || '(none)');

for (const target of findingsCss) {
  const css = buf.subarray(16 + headerSize + target.offset, 16 + headerSize + target.offset + target.size).toString('utf8');
  console.log('\n--- grid template of .findings-filter-toolbar ---');
  const grid = css.match(/\.findings-filter-toolbar[^{]*\{[^}]*\}/);
  console.log(grid ? grid[0].replace(/\s+/g, ' ').slice(0, 600) : '(rule not found)');
  console.log('\n--- finding-filter-clear rules ---');
  for (const rule of (css.match(/\.[^{}]*finding-filter-clear[^{}]*\{[^}]*\}/g) || [])) {
    console.log(rule.replace(/\s+/g, ' '));
  }
  console.log('\n--- finding-task-filter-tag rules ---');
  for (const rule of (css.match(/\.[^{}]*finding-task-filter-tag[^{}]*\{[^}]*\}/g) || [])) {
    console.log(rule.replace(/\s+/g, ' '));
  }
  console.log('\n--- finding-filter-row rules ---');
  for (const rule of (css.match(/\.[^{}]*finding-filter-row[^{}]*\{[^}]*\}/g) || [])) {
    console.log(rule.replace(/\s+/g, ' '));
  }
  console.log('\nhas "finding-filter-trailing":', css.includes('finding-filter-trailing'));
}
