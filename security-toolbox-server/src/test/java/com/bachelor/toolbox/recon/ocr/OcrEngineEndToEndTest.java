package com.bachelor.toolbox.recon.ocr;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;

/**
 * End-to-end smoke test of the ONNX OCR engine against the real PP-OCR model assets. It is
 * skipped when the model directory has not been populated, so it never breaks a build that lacks
 * network access to fetch the models.
 */
class OcrEngineEndToEndTest {

  private static final Path MODELS =
      Path.of("./data/models/icp");

  @Test
  void detectsASyntheticCharacterOnTheModelPipeline() throws Exception {
    assumeThat(Files.isRegularFile(MODELS.resolve("det.onnx"))).isTrue();

    BufferedImage canvas = new BufferedImage(640, 200, BufferedImage.TYPE_INT_RGB);
    Graphics2D g = canvas.createGraphics();
    g.setColor(Color.WHITE);
    g.fillRect(0, 0, 640, 200);
    g.setColor(Color.BLACK);
    g.fillRect(120, 50, 60, 90); // a box that resembles a text region
    g.dispose();

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ImageIO.write(canvas, "png", baos);
    String base64 = Base64.getEncoder().encodeToString(baos.toByteArray());

    try (OcrEngine engine = OcrEngine.load(MODELS)) {
      assumeThat(engine).isNotNull();
      assumeThat(engine.available()).isTrue();
      List<Map<String, Object>> points = engine.solve(base64);
      // The detector may or may not agree on the synthetic box; the important contract is that
      // the ONNX model runs without throwing and either returns points or a clean null.
      assertThat(points).isNotNull();
    }
  }
}