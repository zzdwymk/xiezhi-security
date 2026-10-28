// 从截图上取出某一行像素的颜色，用来判断表格外框（1px 竖线/横线）是否真的画出来了。
// 用法：node scripts/probe-screenshot-pixels.cjs <png> <y> [xStart] [xEnd] [step]
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const [input, yArg, xStartArg, xEndArg, stepArg] = process.argv.slice(2);
const y = Number(yArg);
const xStart = Number(xStartArg ?? 380);
const xEnd = Number(xEndArg ?? 2030);
const step = Number(stepArg ?? 10);

(async () => {
  const browser = await chromium.launch({
    executablePath:
      process.env.TRAFFIC_TEST_BROWSER ||
      'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  const page = await browser.newPage();
  const dataUrl = `data:image/png;base64,${fs.readFileSync(input).toString('base64')}`;
  const rows = await page.evaluate(
    async ([src, y, xStart, xEnd, step]) => {
      const img = new Image();
      await new Promise((r) => {
        img.onload = r;
        img.src = src;
      });
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const out = [];
      for (let x = xStart; x <= xEnd; x += step) {
        const d = ctx.getImageData(x, y, 1, 1).data;
        out.push(`${x}:${d[0]},${d[1]},${d[2]}`);
      }
      return { width: img.width, height: img.height, out };
    },
    [dataUrl, y, xStart, xEnd, step],
  );
  console.log(`image ${rows.width}x${rows.height}, y=${y}`);
  console.log(rows.out.join('  '));
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
