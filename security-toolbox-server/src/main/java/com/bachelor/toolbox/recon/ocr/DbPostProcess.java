package com.bachelor.toolbox.recon.ocr;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Binarization + connected-component box extraction for the MIIT point-challenge background. The
 * DB detection head emits a per-pixel probability map; regions above the box threshold are grouped
 * with a flood fill, and each connected region is summarized as the smallest axis-aligned box that
 * covers it (character glyphs in the challenge are roughly isolated, so an axis-aligned box is a
 * good model).
 */
final class DbPostProcess {

  private final float binaryThreshold;
  private final float boxThreshold;
  private final double minArea;

  DbPostProcess() {
    this.binaryThreshold = 0.3f;
    this.boxThreshold = 0.6f;
    this.minArea = 3;
  }

  /** @param probMap det head output, shape [H][W], values roughly 0..1. */
  List<int[]> boxes(float[][] probMap) {
    int h = probMap.length;
    int w = probMap[0].length;
    byte[] binary = new byte[h * w];
    for (int y = 0; y < h; y++) {
      for (int x = 0; x < w; x++) {
        binary[y * w + x] = probMap[y][x] >= boxThreshold ? (byte) 1 : (byte) 0;
      }
    }

    List<int[]> regions = connectedRegions(binary, w, h);
    List<int[]> boxes = new ArrayList<>();
    for (int[] region : regions) {
      int area = region[2] * region[3];
      if (area < minArea) {
        continue;
      }
      boxes.add(region);
    }
    boxes.sort(Comparator.comparingInt(b -> b[0]));
    return boxes;
  }

  private List<int[]> connectedRegions(byte[] bin, int w, int h) {
    List<int[]> regions = new ArrayList<>();
    boolean[] visited = new boolean[bin.length];
    int[] queue = new int[bin.length];
    int[] dx = {1, -1, 0, 0, 1, 1, -1, -1};
    int[] dy = {0, 0, 1, -1, 1, -1, 1, -1};
    for (int y = 0; y < h; y++) {
      for (int x = 0; x < w; x++) {
        int p = y * w + x;
        if (bin[p] == 0 || visited[p]) {
          continue;
        }
        int minX = x, minY = y, maxX = x, maxY = y, count = 0;
        int head = 0, tail = 0;
        queue[tail++] = p;
        visited[p] = true;
        while (head < tail) {
          int cur = queue[head++];
          int cy = cur / w;
          int cx = cur % w;
          count++;
          if (cx < minX) minX = cx;
          if (cx > maxX) maxX = cx;
          if (cy < minY) minY = cy;
          if (cy > maxY) maxY = cy;
          for (int d = 0; d < 8; d++) {
            int nx = cx + dx[d];
            int ny = cy + dy[d];
            if (nx < 0 || nx >= w || ny < 0 || ny >= h) continue;
            int np = ny * w + nx;
            if (bin[np] == 0 || visited[np]) continue;
            visited[np] = true;
            queue[tail++] = np;
          }
        }
        regions.add(new int[] {minX, minY, maxX - minX + 1, maxY - minY + 1});
      }
    }
    return regions;
  }
}