package com.bachelor.toolbox.recon;

import com.bachelor.toolbox.recon.ocr.OcrEngine;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Automatic solver for the MIIT "click the matching characters" point challenge.
 *
 * <p>When the PaddleOCR model assets ({@code det.onnx}, {@code rec.onnx},
 * {@code ppocr_keys_v1.txt}) are available under the configured ICT model directory, this class
 * detects the character boxes in the background image with the local ONNX Runtime engine and
 * returns their coordinates. When the models are not present (or the engine cannot resolve the
 * challenge confidently) it returns {@code null}, so {@link MiitIcpClient} reports
 * {@code CAPTCHA_REQUIRED} and the caller falls back to the manual data source.
 */
final class MiitCaptchaSolver {

  private MiitCaptchaSolver() {}

  /** Default models directory; override with the ICP_OCR_MODELS environment variable. */
  static final String DEFAULT_MODELS_PATH = "./data/models/icp";

  /**
   * @param bigImage base64-encoded background image
   * @param smallImage base64-encoded character strip (accepted for API symmetry)
   * @return ordered points in image coordinates, or {@code null} when not resolved automatically
   */
  static List<Map<String, Object>> solve(String bigImage, String smallImage) {
    return solve(bigImage, smallImage, null);
  }

  static List<Map<String, Object>> solve(String bigImage, String smallImage, String modelsPath) {
    if (bigImage == null
        || bigImage.isBlank()
        || smallImage == null
        || smallImage.isBlank()) {
      return null;
    }
    try {
      OcrEngine engine = OcrEngine.load(modelsPath == null ? modelsPath() : Path.of(modelsPath));
      if (engine == null || !engine.available()) {
        return null;
      }
      try (engine) {
        List<Map<String, Object>> points = engine.solve(bigImage);
        if (points == null || points.isEmpty()) {
          return null;
        }
        return points;
      }
    } catch (Exception exception) {
      return null;
    }
  }

  private static Path modelsPath() {
    String configured = System.getenv("ICP_OCR_MODELS");
    if (configured == null || configured.isBlank()) {
      configured = System.getProperty("toolbox.recon.icp-ocr-models-path");
    }
    return configured == null || configured.isBlank()
        ? Path.of(DEFAULT_MODELS_PATH)
        : Path.of(configured);
  }
}