// 诊断：比对 dist、.toolbox-build-manifest.json 与桌面端 app.asar，回答
// “为什么跑了 package-desktop-release.cmd，桌面端却没带上最新改动”。
// 只用 node 原生模块，输出为 ASCII 标签 + 原始值，任何终端都不会乱码。
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const frontend = path.resolve(__dirname, '..');
const distIndex = path.join(frontend, 'dist', 'index.html');
const manifestPath = path.join(frontend, '.toolbox-build-manifest.json');
const asarPath = path.join(frontend, 'desktop-release', 'win-unpacked', 'resources', 'app.asar');

// 与 package-desktop-release.ps1 的 $frontendExcludes 保持一致。
const excludes = ['dist', 'node_modules', 'desktop-release', '.git', 'target', '.next', '.toolbox-build-manifest.json'];

function stat(target) {
  try {
    const info = fs.statSync(target);
    return { exists: true, mtime: info.mtime, size: info.size };
  } catch {
    return { exists: false, mtime: null, size: 0 };
  }
}

function newestSource() {
  let newest = null;
  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      // 无权限或刚被删除的目录（例如 pytest 缓存）直接跳过。
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (excludes.some((pattern) => full.includes(pattern))) continue;
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      let info;
      try {
        info = fs.statSync(full);
      } catch {
        continue;
      }
      if (!newest || info.mtimeMs > newest.mtimeMs) newest = { path: full, mtime: info.mtime, mtimeMs: info.mtimeMs };
    }
  };
  walk(frontend);
  return newest;
}

function entryFromHtml(html) {
  const match = html.match(/src="([^"]*assets\/index-[^"]+\.js)"/);
  return match ? match[1] : null;
}

function asarEntry() {
  if (!fs.existsSync(asarPath)) return { exists: false, entry: null, findings: [] };
  const buffer = fs.readFileSync(asarPath);
  const headerSize = buffer.readUInt32LE(12);
  const text = buffer.subarray(16 + headerSize).toString('utf8');
  const header = JSON.parse(buffer.subarray(16, 16 + headerSize).toString('utf8'));
  const files = [];
  const walk = (node, prefix) => {
    for (const [name, value] of Object.entries(node.files || {})) {
      const next = `${prefix}/${name}`;
      if (value.files) walk(value, next);
      else files.push(next);
    }
  };
  walk(header, '');
  return {
    exists: true,
    entry: entryFromHtml(text),
    findings: files.filter((file) => /\/Findings-[A-Za-z0-9_-]+\.(js|css)$/.test(file)),
  };
}

const dist = stat(distIndex);
const manifest = stat(manifestPath);
const html = dist.exists ? fs.readFileSync(distIndex, 'utf8') : '';
const distEntry = entryFromHtml(html);
const packaged = asarEntry();
const src = newestSource();

const fmt = (date) => (date ? date.toISOString().replace('T', ' ').slice(0, 19) + 'Z' : '-');

console.log('[dist]');
console.log('  index.html mtime :', fmt(dist.mtime));
console.log('  entry            :', distEntry);
console.log('  mode             :', distEntry ? (distEntry.startsWith('./') ? 'desktop (base ./)' : 'web (base /)') : 'unknown');
console.log('[manifest]');
console.log('  mtime            :', fmt(manifest.mtime));
console.log('[asar]');
console.log('  app.asar mtime   :', fmt(stat(asarPath).mtime));
console.log('  entry            :', packaged.entry);
console.log('  findings assets  :', packaged.findings.join(', ') || '(none)');
console.log('[sources]');
console.log('  newest renderer  :', src ? `${fmt(src.mtime)} ${path.relative(frontend, src.path)}` : '-');

console.log('[verdict]');
let problem = false;
if (distEntry && !distEntry.startsWith('./')) {
  console.log('  ! dist is a WEB build (base /): Electron file:// cannot load it.');
  problem = true;
}
if (manifest.mtime && dist.mtime && manifest.mtime > dist.mtime) {
  console.log('  ! dist/index.html is OLDER than the build manifest.');
  problem = true;
}
if (src && dist.mtime && src.mtime > dist.mtime) {
  console.log('  ! dist/index.html is OLDER than the newest source file.');
  problem = true;
}
if (packaged.exists && packaged.entry && distEntry && packaged.entry !== distEntry) {
  console.log(`  ! packaged entry (${packaged.entry}) != dist entry (${distEntry}): asar was not built from this dist.`);
  problem = true;
}
if (!src || !manifest.mtime || !dist.mtime) problem = true;
console.log(problem ? '  => desktop release may ship a stale renderer.' : '  => dist, manifest and asar are consistent.');
process.exitCode = problem ? 1 : 0;
