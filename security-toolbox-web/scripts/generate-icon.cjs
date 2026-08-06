// Builds the Xiezhi application icon from the selected shield artwork.
// The source is kept in the repository so PNG/ICO assets are reproducible.
const fs = require("fs");
const path = require("path");
const { PNG } = require("pngjs");
const pngToIcoModule = require("png-to-ico");
const pngToIco = pngToIcoModule.default || pngToIcoModule;

const CROP = { x: 0, y: 0, size: 1600 };
const SHIELD = [
  [800, 0],
  [735, 50],
  [620, 115],
  [480, 180],
  [310, 235],
  [165, 270],
  [85, 320],
  [85, 670],
  [120, 900],
  [220, 1130],
  [360, 1320],
  [535, 1460],
  [680, 1550],
  [800, 1600],
  [920, 1550],
  [1065, 1460],
  [1240, 1320],
  [1380, 1130],
  [1480, 900],
  [1515, 670],
  [1515, 320],
  [1435, 270],
  [1290, 235],
  [1120, 180],
  [980, 115],
  [865, 50],
];
const BG_TOP = [5, 20, 41];
const BG_BOTTOM = [8, 50, 82];

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function lerp(a, b, t) {
  return [
    a[0] + (b[0] - a[0]) * t,
    a[1] + (b[1] - a[1]) * t,
    a[2] + (b[2] - a[2]) * t,
  ];
}

function inRoundedSquare(x, y, size) {
  const half = size / 2;
  const radius = size * 0.19;
  const qx = Math.abs(x) - (half - radius);
  const qy = Math.abs(y) - (half - radius);
  if (qx <= 0 && qy <= 0) return true;
  return Math.max(qx, 0) ** 2 + Math.max(qy, 0) ** 2 <= radius * radius;
}

function inPolygon(x, y, points) {
  let inside = false;
  for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
    const [xi, yi] = points[i];
    const [xj, yj] = points[j];
    const intersects =
      yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi;
    if (intersects) inside = !inside;
  }
  return inside;
}

function sourcePixel(source, x, y) {
  const x0 = clamp(Math.floor(x), 0, source.width - 1);
  const y0 = clamp(Math.floor(y), 0, source.height - 1);
  const x1 = clamp(x0 + 1, 0, source.width - 1);
  const y1 = clamp(y0 + 1, 0, source.height - 1);
  const tx = x - Math.floor(x);
  const ty = y - Math.floor(y);

  function pixel(px, py) {
    const index = (py * source.width + px) << 2;
    return [source.data[index], source.data[index + 1], source.data[index + 2]];
  }

  const top = lerp(pixel(x0, y0), pixel(x1, y0), tx);
  const bottom = lerp(pixel(x0, y1), pixel(x1, y1), tx);
  return lerp(top, bottom, ty);
}

function sampleColor(source, sx, sy, size) {
  const x = sx - size / 2;
  const y = sy - size / 2;
  if (!inRoundedSquare(x, y, size)) return null;

  const gradient = clamp((sx / size + sy / size) / 2, 0, 1);
  let color = lerp(BG_TOP, BG_BOTTOM, gradient);

  const padding = size * 0.025;
  const contentSize = size - padding * 2;
  const u = (sx - padding) / contentSize;
  const v = (sy - padding) / contentSize;
  if (u >= 0 && u <= 1 && v >= 0 && v <= 1) {
    const localX = u * CROP.size;
    const localY = v * CROP.size;
    if (inPolygon(localX, localY, SHIELD)) {
      color = sourcePixel(source, CROP.x + localX, CROP.y + localY);
    }
  }
  return color;
}

function render(source, size) {
  const png = new PNG({ width: size, height: size });
  const samples = size <= 32 ? 6 : 4;
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let covered = 0;
      for (let sampleY = 0; sampleY < samples; sampleY++) {
        for (let sampleX = 0; sampleX < samples; sampleX++) {
          const sx = px + (sampleX + 0.5) / samples;
          const sy = py + (sampleY + 0.5) / samples;
          const color = sampleColor(source, sx, sy, size);
          if (!color) continue;
          r += color[0];
          g += color[1];
          b += color[2];
          covered++;
        }
      }
      const index = (py * size + px) << 2;
      const count = samples * samples;
      png.data[index] = covered ? Math.round(r / covered) : 0;
      png.data[index + 1] = covered ? Math.round(g / covered) : 0;
      png.data[index + 2] = covered ? Math.round(b / covered) : 0;
      png.data[index + 3] = Math.round((covered / count) * 255);
    }
  }
  return PNG.sync.write(png);
}

async function main() {
  const projectRoot = path.resolve(__dirname, "..");
  const buildDir = path.join(projectRoot, "build");
  const electronDir = path.join(projectRoot, "electron");
  const sourceAssetDir = path.join(projectRoot, "src", "assets");
  const sourcePath = path.join(buildDir, "xiezhi-logo-source.png");
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Selected Xiezhi source artwork is missing: ${sourcePath}`);
  }

  const source = PNG.sync.read(fs.readFileSync(sourcePath));
  if (source.width < CROP.x + CROP.size || source.height < CROP.y + CROP.size) {
    throw new Error(`Unexpected source size: ${source.width}x${source.height}`);
  }

  fs.mkdirSync(sourceAssetDir, { recursive: true });
  const sizes = [256, 128, 64, 48, 32, 24, 16];
  const buffers = sizes.map((size) => render(source, size));
  const mainPng = render(source, 512);
  fs.writeFileSync(path.join(buildDir, "icon.png"), mainPng);
  fs.writeFileSync(path.join(electronDir, "icon.png"), mainPng);
  fs.writeFileSync(path.join(sourceAssetDir, "xiezhi-mark.png"), mainPng);
  const ico = await pngToIco(buffers);
  fs.writeFileSync(path.join(buildDir, "icon.ico"), ico);
  console.log("Selected shield artwork written to PNG/ICO assets.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
