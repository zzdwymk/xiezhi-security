package com.bachelor.toolbox.recon.ocr;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.image.BufferedImage;
import org.junit.jupiter.api.Test;

class OcrRecognitionPreprocessingTests {
  @Test
  void convertsDetectionWidthsToAbsoluteRightBottomCoordinates() {
    assertThat(OcrEngine.detectionRegionToBox(new int[] {100, 50, 60, 90}, 0.5f, 0.5f))
        .containsExactly(50, 25, 80, 70);
  }

  @Test
  void centersBlackAndWhiteChannelsToMinusOneAndOne() {
    BufferedImage image = new BufferedImage(2, 1, BufferedImage.TYPE_INT_RGB);
    image.setRGB(0, 0, 0x000000);
    image.setRGB(1, 0, 0xffffff);
    assertThat(OcrEngine.recognitionInput(image, 1, 2))
        .containsExactly(-1f, 1f, -1f, 1f, -1f, 1f);
  }

  @Test
  void preservesBgrOrderAndZeroPadsInsteadOfStretchingNarrowText() {
    BufferedImage image = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
    image.setRGB(0, 0, 0xff0000);
    assertThat(OcrEngine.recognitionInput(image, 1, 4))
        .containsExactly(-1f, 0f, 0f, 0f, -1f, 0f, 0f, 0f, 1f, 0f, 0f, 0f);
  }
}
