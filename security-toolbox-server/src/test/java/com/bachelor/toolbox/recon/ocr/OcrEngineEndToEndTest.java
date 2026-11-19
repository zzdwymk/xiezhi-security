package com.bachelor.toolbox.recon.ocr;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import java.awt.Color;
import java.awt.Font;
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

/** Optional only when no models are configured; configured or partial models must pass, not skip. */
class OcrEngineEndToEndTest {
  @Test
  void detectsAndRecognizesKnownTextOnTheModelPipeline() throws Exception {
    String configured = System.getenv("ICP_OCR_MODELS");
    if (configured == null || configured.isBlank()) {
      configured = System.getProperty("toolbox.recon.icp-ocr-models-path");
    }
    boolean explicit = configured != null && !configured.isBlank();
    Path models = Path.of(explicit ? configured : "./data/models/icp");
    List<String> assets = List.of("det.onnx", "rec.onnx", "ppocr_keys_v1.txt");
    if (!explicit && assets.stream().noneMatch(name -> Files.exists(models.resolve(name)))) {
      assumeThat(false).as("Real OCR assets not configured; use scripts/fetch-ocr-e2e-models.py").isTrue();
    }
    for (String asset : assets) {
      assertThat(Files.isRegularFile(models.resolve(asset))).as("Required OCR asset: %s", models.resolve(asset)).isTrue();
    }

    BufferedImage canvas = new BufferedImage(320, 128, BufferedImage.TYPE_INT_RGB);
    Graphics2D g = canvas.createGraphics();
    g.setColor(Color.WHITE);
    g.fillRect(0, 0, canvas.getWidth(), canvas.getHeight());
    g.setColor(Color.BLACK);
    g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 64));
    g.drawString("TEST", 50, 90);
    g.dispose();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ImageIO.write(canvas, "png", baos);
    String base64 = Base64.getEncoder().encodeToString(baos.toByteArray());

    try (OcrEngine engine = OcrEngine.load(models)) {
      assertThat(engine).as("Configured real OCR models must load successfully").isNotNull();
      assertThat(engine.available()).isTrue();
      List<Map<String, Object>> points = engine.solve(base64);
      assertThat(points).as("Printed text must produce detector points").isNotEmpty();
      for (Map<String, Object> point : points) {
        assertThat(((Number) point.get("x")).intValue()).isBetween(0, canvas.getWidth() - 1);
        assertThat(((Number) point.get("y")).intValue()).isBetween(0, canvas.getHeight() - 1);
      }
      var recognize = OcrEngine.class.getDeclaredMethod("recognize", BufferedImage.class, int[].class);
      recognize.setAccessible(true);
      String text = (String) recognize.invoke(engine, canvas, new int[] {20, 20, 290, 115});
      assertThat(text).as("Real recognizer must decode the known printed word").isEqualTo("TEST");
      var detect = OcrEngine.class.getDeclaredMethod("detect", BufferedImage.class);
      detect.setAccessible(true);
      @SuppressWarnings("unchecked")
      List<int[]> boxes = (List<int[]>) detect.invoke(engine, canvas);
      List<String> candidateTexts = new java.util.ArrayList<>();
      for (int[] box : boxes) candidateTexts.add((String) recognize.invoke(engine, canvas, box));
      var stripChars = OcrEngine.class.getDeclaredMethod("stripChars", BufferedImage.class);
      stripChars.setAccessible(true);
      Object requested = stripChars.invoke(engine, canvas);
      List<String> coordinates = boxes.stream().map(java.util.Arrays::toString).toList();
      assertThat(engine.solve(base64, base64)).as("Real matching: boxes=%s candidates=%s requested=%s", coordinates, candidateTexts, requested).isNotEmpty();
    }
  }
}
