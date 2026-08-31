package com.bachelor.toolbox.recon.ocr;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class DbPostProcessTest {

  @Test
  void isolatesTwoCharacterRegions() {
    // 24x12 map with two distinct blobs above the box threshold.
    int w = 24, h = 12;
    float[][] map = new float[h][w];
    for (int y = 2; y < 6; y++) {
      for (int x = 3; x < 8; x++) map[y][x] = 0.9f; // first blob
      for (int x = 14; x < 20; x++) map[y][x] = 0.9f; // second blob
    }
    DbPostProcess db = new DbPostProcess();
    List<int[]> boxes = db.boxes(map);
    assertThat(boxes).hasSize(2);
    assertThat(boxes.get(0)).isEqualTo(new int[] {3, 2, 5, 4});
    assertThat(boxes.get(1)).isEqualTo(new int[] {14, 2, 6, 4});
  }

  @Test
  void dropsRegionsBelowTheMinimumArea() {
    int w = 8, h = 8;
    float[][] map = new float[h][w];
    // Single pixel blob should be discarded by the area filter.
    map[4][4] = 0.9f;
    DbPostProcess db = new DbPostProcess();
    assertThat(db.boxes(map)).isEmpty();
  }
}