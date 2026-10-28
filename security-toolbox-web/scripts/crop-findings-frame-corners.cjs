// 裁切并放大「安全发现」表格角部，用于肉眼核对四边外框是否连续。
// 用法：node scripts/crop-findings-frame-corners.cjs <png> [outDir]
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const input = process.argv[2];
const outDir = process.argv[3] || path.join(path.dirname(input), 'corners');
fs.mkdirSync(outDir, { recursive: true });
const dataUrl = `data:image/png;base64,${fs.readFileSync(input).toString('base64')}`;

(async () => {
  const browser = await chromium.launch({
    executablePath:
      process.env.TRAFFIC_TEST_BROWSER ||
      'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1200, height: 800 } });
  await page.setContent(
    `<html><body style="margin:0;background:#fff"><canvas id="c"></canvas>
     <script>
       window.crop = async (src, sx, sy, sw, sh, scale) => {
         const img = new Image();
         await new Promise((r) => { img.onload = r; img.src = src; });
         const c = document.getElementById('c');
         c.width = sw * scale; c.height = sh * scale;
         const ctx = c.getContext('2d');
         ctx.imageSmoothingEnabled = false;
         ctx.drawImage(img, sx, sy, sw, sh, 0, 0, sw * scale, sh * scale);
         return c.toDataURL('image/png');
       };
     </script></body></html>`,
  );
  // 表格几何（1440x1000 视口下由 verify-findings-table-frame.cjs 测得）：x 280 y 262 w 1135 h 568
  const regions = {
    'corner-top-left': [280, 262, 180, 120, 4],
    'corner-top-right': [1235, 262, 180, 120, 4],
    'corner-bottom-left': [280, 690, 180, 140, 4],
    'edge-right-middle': [1330, 400, 90, 160, 4],
  };
  for (const [name, [sx, sy, sw, sh, scale]] of Object.entries(regions)) {
    const url = await page.evaluate(
      ([src, a, b, c, d, s]) => window.crop(src, a, b, c, d, s),
      [dataUrl, sx, sy, sw, sh, scale],
    );
    fs.writeFileSync(
      path.join(outDir, `${name}.png`),
      Buffer.from(url.split(',')[1], 'base64'),
    );
    console.log(`saved ${name}.png`);
  }
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
