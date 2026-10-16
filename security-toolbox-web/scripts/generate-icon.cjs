// Builds the Xiezhi application icon assets from the shield artwork.
//
// The source artwork (build/xiezhi-logo-source.png) is the flattenend design
// render: the shield sits on a light (checkerboard) backdrop. This script
// derives a proper alpha silhouette instead of relying on that backdrop:
//
//   1. anything enclosed by the dark shield outline is artwork,
//   2. the horn slot at the shield crest is sealed so the flood fill from the
//      canvas border cannot leak into the horn,
//   3. edge pixels are un-blended against the backdrop colour, which removes
//      the pale fringe that would otherwise read as a halo/border when the
//      icon is placed on a dark surface,
//   4. the result is cropped to the artwork bounding box so the shield fills
//      its container instead of floating in the middle of a padded canvas.
//
// Outputs (all tightly cropped, transparent background):
// - build/icon.ico                Windows multi-resolution application icon
// - build/icon.png                512x512 installer / desktop icon
// - electron/icon.png             512x512 Electron window + startup splash icon
// - src/assets/xiezhi-mark.png    512x512 in-app brand mark
const fs = require("fs");
const path = require("path");
const { PNG } = require("pngjs");
const pngToIcoModule = require("png-to-ico");
const pngToIco = pngToIcoModule.default || pngToIcoModule;

// Fraction of the source backdrop that stays as padding around the artwork.
const ARTWORK_PADDING = 0.02;

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

function readBackdropColor(source) {
  const { width, height, data } = source;
  let r = 0;
  let g = 0;
  let b = 0;
  let count = 0;
  const ring = Math.max(4, Math.round(Math.min(width, height) * 0.008));
  const push = (x, y) => {
    const index = (y * width + x) << 2;
    r += data[index];
    g += data[index + 1];
    b += data[index + 2];
    count++;
  };
  for (let y = 0; y < ring; y++) {
    for (let x = 0; x < width; x++) {
      push(x, y);
      push(x, height - 1 - y);
    }
  }
  for (let x = 0; x < ring; x++) {
    for (let y = ring; y < height - ring; y++) {
      push(x, y);
      push(width - 1 - x, y);
    }
  }
  return [r / count, g / count, b / count];
}

// 1. Dark shield outline: the flood fill barrier.
function buildOutlineBarrier(source) {
  const { width, height, data } = source;
  const barrier = new Uint8Array(width * height);
  for (let y = 0; y < height; y++) {
    const rowOffset = y * width;
    for (let x = 0; x < width; x++) {
      const index = (rowOffset + x) << 2;
      if (
        data[index] < 190 &&
        data[index + 1] < 190 &&
        data[index + 2] < 190
      ) {
        barrier[rowOffset + x] = 1;
      }
    }
  }
  return barrier;
}

// 2. Locate the horn slot at the shield crest and cap it. Without the cap the
//    fill from the canvas border runs down the pale horn and eats it away.
function sealCrestSlot(source, barrier) {
  const { width, height, data } = source;
  const isArtwork = (x, y) => {
    const index = (y * width + x) << 2;
    const r = data[index];
    const g = data[index + 1];
    const b = data[index + 2];
    return Math.min(r, g, b) < 220 || Math.max(r, g, b) - Math.min(r, g, b) > 25;
  };

  let topDark = -1;
  let minX = width;
  let maxX = -1;
  for (let y = 0; y < height && topDark < 0; y++) {
    for (let x = 0; x < width; x++) {
      if (barrier[y * width + x]) {
        topDark = y;
        break;
      }
    }
  }
  if (topDark < 0) return new Uint8Array(width * height);

  for (let y = topDark; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (isArtwork(x, y)) {
        if (x < minX) minX = x;
        if (x > maxX) maxX = x;
      }
    }
  }

  const band = Math.max(4, Math.round(height * 0.006));
  const hasDark = new Uint8Array(width);
  for (let x = minX; x <= maxX; x++) {
    for (let y = topDark; y <= Math.min(height - 1, topDark + band); y++) {
      if (barrier[y * width + x]) {
        hasDark[x] = 1;
        break;
      }
    }
  }

  // Widest enclosed gap = the horn slot.
  let best = null;
  let x = minX;
  while (x <= maxX) {
    if (hasDark[x]) {
      x++;
      continue;
    }
    const start = x;
    while (x <= maxX && !hasDark[x]) x++;
    const end = x - 1;
    if (start > minX && end < maxX) {
      const size = end - start + 1;
      if (!best || size > best.size) best = { start, end, size };
    }
  }

  const seal = new Uint8Array(width * height);
  if (!best) return seal;

  // Cap the slot on the single row directly above the crest. With 4-connected
  // fill, blocking that one row is enough to close the opening, and it keeps
  // the clip out of the horn tip below.
  const capY = topDark - 1;
  if (capY < 0) return seal;
  const from = Math.max(0, best.start - 3);
  const to = Math.min(width - 1, best.end + 3);
  for (let xx = from; xx <= to; xx++) {
    const index = capY * width + xx;
    if (barrier[index]) continue;
    barrier[index] = 1;
    seal[index] = 1;
  }
  return seal;
}

function floodFillOutside(source, barrier) {
  const { width, height } = source;
  const visited = new Uint8Array(width * height);
  const queue = new Int32Array(width * height);
  let head = 0;
  let tail = 0;

  visited[0] = 1;
  queue[tail++] = 0;

  while (head < tail) {
    const current = queue[head++];
    const cx = current % width;
    const cy = (current - cx) / width;
    const up = cy > 0 ? current - width : -1;
    const down = cy < height - 1 ? current + width : -1;
    const left = cx > 0 ? current - 1 : -1;
    const right = cx < width - 1 ? current + 1 : -1;
    if (up >= 0 && !visited[up] && !barrier[up]) {
      visited[up] = 1;
      queue[tail++] = up;
    }
    if (down >= 0 && !visited[down] && !barrier[down]) {
      visited[down] = 1;
      queue[tail++] = down;
    }
    if (left >= 0 && !visited[left] && !barrier[left]) {
      visited[left] = 1;
      queue[tail++] = left;
    }
    if (right >= 0 && !visited[right] && !barrier[right]) {
      visited[right] = 1;
      queue[tail++] = right;
    }
  }
  return visited;
}

function buildSilhouette(source) {
  const { width, height, data } = source;
  const barrier = buildOutlineBarrier(source);
  const seal = sealCrestSlot(source, barrier);
  const visited = floodFillOutside(source, barrier);

  const mask = new Uint8Array(width * height);
  for (let i = 0; i < mask.length; i++) {
    // Seal pixels sit in the backdrop, so they must not join the silhouette...
    if (!visited[i] && !seal[i]) mask[i] = 1;
  }

  // ...but leaving the cap row transparent would nick the crest. Rebuild it
  // from the artwork directly beneath, so the horn tip stays solid.
  for (let i = 0; i < seal.length; i++) {
    if (!seal[i]) continue;
    const x = i % width;
    const y = (i - x) / width;
    let source_y = y + 1;
    while (source_y < height && !mask[source_y * width + x]) source_y++;
    if (source_y >= height) continue;
    const fromIndex = (source_y * width + x) << 2;
    const toIndex = i << 2;
    data[toIndex] = data[fromIndex];
    data[toIndex + 1] = data[fromIndex + 1];
    data[toIndex + 2] = data[fromIndex + 2];
    mask[i] = 1;
  }
  return mask;
}

// 4. Crop to the artwork bounding box, padded out to a square so every icon
//    size keeps the original proportions.
function artworkViewport(mask, width, height) {
  let minX = width;
  let minY = height;
  let maxX = -1;
  let maxY = -1;
  for (let y = 0; y < height; y++) {
    const rowOffset = y * width;
    for (let x = 0; x < width; x++) {
      if (!mask[rowOffset + x]) continue;
      if (x < minX) minX = x;
      if (x > maxX) maxX = x;
      if (y < minY) minY = y;
      if (y > maxY) maxY = y;
    }
  }
  if (maxX < 0) throw new Error("Artwork silhouette is empty.");

  const boxW = maxX - minX + 1;
  const boxH = maxY - minY + 1;
  const size = Math.max(boxW, boxH) * (1 + ARTWORK_PADDING * 2);
  const centerX = (minX + maxX + 1) / 2;
  const centerY = (minY + maxY + 1) / 2;
  return {
    x: centerX - size / 2,
    y: centerY - size / 2,
    size,
    boxW,
    boxH,
  };
}

function sampleMask(mask, width, height, x, y) {
  const x0 = clamp(Math.floor(x), 0, width - 1);
  const y0 = clamp(Math.floor(y), 0, height - 1);
  const x1 = clamp(x0 + 1, 0, width - 1);
  const y1 = clamp(y0 + 1, 0, height - 1);
  const tx = clamp(x - Math.floor(x), 0, 1);
  const ty = clamp(y - Math.floor(y), 0, 1);
  const a = mask[y0 * width + x0];
  const b = mask[y0 * width + x1];
  const c = mask[y1 * width + x0];
  const d = mask[y1 * width + x1];
  const top = a + (b - a) * tx;
  const bottom = c + (d - c) * tx;
  return top + (bottom - top) * ty;
}

function sampleColor(source, x, y) {
  const { width, height, data } = source;
  const x0 = clamp(Math.floor(x), 0, width - 1);
  const y0 = clamp(Math.floor(y), 0, height - 1);
  const x1 = clamp(x0 + 1, 0, width - 1);
  const y1 = clamp(y0 + 1, 0, height - 1);
  const tx = clamp(x - Math.floor(x), 0, 1);
  const ty = clamp(y - Math.floor(y), 0, 1);

  const pixel = (px, py) => {
    const index = (py * width + px) << 2;
    return [data[index], data[index + 1], data[index + 2]];
  };

  const top = lerp(pixel(x0, y0), pixel(x1, y0), tx);
  const bottom = lerp(pixel(x0, y1), pixel(x1, y1), tx);
  return lerp(top, bottom, ty);
}

// 3. Recover the artwork colour from a partly covered pixel. The backdrop is
//    light and the shield outline is dark, so leaving the blend in place is
//    exactly what produces a pale rim on dark surfaces.
function unblend(color, coverage, backdrop) {
  if (coverage >= 0.999) return color;
  const a = Math.max(coverage, 0.08);
  return [
    clamp((color[0] - (1 - a) * backdrop[0]) / a, 0, 255),
    clamp((color[1] - (1 - a) * backdrop[1]) / a, 0, 255),
    clamp((color[2] - (1 - a) * backdrop[2]) / a, 0, 255),
  ];
}

function render(source, mask, backdrop, viewport, size) {
  const png = new PNG({ width: size, height: size });
  const samples = size <= 32 ? 6 : 4;
  const total = samples * samples;

  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let alphaSum = 0;

      for (let sy = 0; sy < samples; sy++) {
        for (let sx = 0; sx < samples; sx++) {
          const outX = px + (sx + 0.5) / samples;
          const outY = py + (sy + 0.5) / samples;
          const srcX = viewport.x + (outX / size) * viewport.size;
          const srcY = viewport.y + (outY / size) * viewport.size;

          const coverage = sampleMask(
            mask,
            source.width,
            source.height,
            srcX,
            srcY,
          );
          if (coverage <= 0.01) continue;

          const foreground = unblend(
            sampleColor(source, srcX, srcY),
            coverage,
            backdrop,
          );
          r += foreground[0] * coverage;
          g += foreground[1] * coverage;
          b += foreground[2] * coverage;
          alphaSum += coverage;
        }
      }

      const index = (py * size + px) << 2;
      png.data[index] = alphaSum > 0 ? Math.round(r / alphaSum) : 0;
      png.data[index + 1] = alphaSum > 0 ? Math.round(g / alphaSum) : 0;
      png.data[index + 2] = alphaSum > 0 ? Math.round(b / alphaSum) : 0;
      png.data[index + 3] = Math.round(clamp(alphaSum / total, 0, 1) * 255);
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
  const backdrop = readBackdropColor(source);
  const mask = buildSilhouette(source);
  const viewport = artworkViewport(mask, source.width, source.height);
  const render1 = (size) => render(source, mask, backdrop, viewport, size);

  let covered = 0;
  for (let i = 0; i < mask.length; i++) covered += mask[i];
  console.log(
    `Source ${source.width}x${source.height}; backdrop rgb(${backdrop
      .map((v) => Math.round(v))
      .join(", ")}); silhouette ${covered} px; crop ${Math.round(
      viewport.size,
    )}x${Math.round(viewport.size)}`,
  );

  const sizes = [256, 128, 64, 48, 32, 24, 16];
  const buffers = sizes.map(render1);
  const mainPng = render1(512);

  fs.mkdirSync(sourceAssetDir, { recursive: true });
  fs.writeFileSync(path.join(buildDir, "icon.png"), mainPng);
  fs.writeFileSync(path.join(electronDir, "icon.png"), mainPng);
  fs.writeFileSync(path.join(sourceAssetDir, "xiezhi-mark.png"), mainPng);

  const ico = await pngToIco(buffers);
  fs.writeFileSync(path.join(buildDir, "icon.ico"), ico);

  console.log(
    "Updated build/icon.ico, build/icon.png, electron/icon.png, src/assets/xiezhi-mark.png",
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
