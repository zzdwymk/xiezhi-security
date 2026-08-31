package com.bachelor.toolbox.recon.ocr;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtSession;
import ai.onnxruntime.TensorInfo;
import java.awt.image.BufferedImage;
import java.nio.FloatBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Java / ONNX-Runtime recognizer for the MIIT point-challenge images, using the PaddleOCR
 * (PP-OCR) model family exported to ONNX. The models and the character dictionary are loaded from a
 * configurable models directory:
 *
 * <ul>
 *   <li>{@code det.onnx} - DB text detection, emitting a WxH probability map
 *   <li>{@code rec.onnx} - recognition model (report: exact numeric decoding)
 *   <li>{@code ppocr_keys_v1.txt} - PaddleOCR dictionary
 * </ul>
 *
 * <p>When the model assets are absent, {@link #available()} is {@code false} and the caller keeps
 * the existing manual point-selection flow, so the server always builds and runs. The pure-Java
 * numerics (binary connected-component box extraction and CTC collapse decode) are covered by unit
 * tests; the neural models themselves are supplied by the administrator and must be calibrated
 * against the operator-verified flow.
 */
public final class OcrEngine implements AutoCloseable {

  private static final float[] DET_MEAN = {0.485f, 0.456f, 0.406f};
  private static final float[] DET_STD = {0.229f, 0.224f, 0.225f};

  private final OrtEnvironment env;
  private final OrtSession detSession;
  private final OrtSession recSession;
  private final DbPostProcess db;

  private OcrEngine(OrtEnvironment env, OrtSession detSession, OrtSession recSession) {
    this.env = env;
    this.detSession = detSession;
    this.recSession = recSession;
    this.db = new DbPostProcess();
  }

  /** Builds the engine when all model assets are present, otherwise returns {@code null}. */
  public static OcrEngine load(Path modelDir) {
    if (modelDir == null) {
      return null;
    }
    Path det = modelDir.resolve("det.onnx");
    Path rec = modelDir.resolve("rec.onnx");
    Path dict = modelDir.resolve("ppocr_keys_v1.txt");
    if (!Files.isRegularFile(det) || !Files.isRegularFile(rec) || !Files.isRegularFile(dict)) {
      return null;
    }
    try {
      // Validate the dictionary is parseable so a corrupt asset fails fast at load time.
      CtcDecode.fromDictFile(dict);
      OrtEnvironment env = OrtEnvironment.getEnvironment();
      return new OcrEngine(env, env.createSession(det.toString()), env.createSession(rec.toString()));
    } catch (Exception exception) {
      return null;
    }
  }

  public boolean available() {
    return detSession != null && recSession != null;
  }

  /**
   * Attempts to resolve the point challenge: returns the upper-left coordinates of the character
   * boxes detected in the background image, or {@code null} when it cannot resolve the challenge.
   */
  public List<Map<String, Object>> solve(String bigImage) {
    if (!available()) {
      return null;
    }
    try {
      BufferedImage big = ImageOps.fromBase64(bigImage);
      List<int[]> boxes = detect(big);
      if (boxes.isEmpty()) {
        return null;
      }
      List<Map<String, Object>> out = new ArrayList<>();
      for (int[] box : boxes) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("x", box[0]);
        p.put("y", box[1]);
        out.add(p);
      }
      return out;
    } catch (Exception exception) {
      return null;
    }
  }

  private List<int[]> detect(BufferedImage image) throws Exception {
    String inputName = new ArrayList<>(detSession.getInputInfo().keySet()).get(0);
    TensorInfo info = (TensorInfo) detSession.getInputInfo().get(inputName).getInfo();
    long[] declaredShape = info.getShape();
    int declaredH = intDim(declaredShape, declaredShape.length - 2, -1);
    int declaredW = intDim(declaredShape, declaredShape.length - 1, -1);
    int channels = intDim(declaredShape, declaredShape.length - 3, 3);

    // PP-OCR detection resizes so the longer side is DET_LIMIT_SIDE_LEN and keeps aspect ratio,
    // and it rounds the short side to a multiple of 32 for the conv stride.
    int detLimit = 640;
    int srcW = image.getWidth();
    int srcH = image.getHeight();
    int inH = declaredH > 0 ? declaredH : (int) Math.max(32, Math.round(srcH / (double) Math.max(srcH, srcW) * detLimit / 32.0) * 32);
    int inW = declaredW > 0 ? declaredW : (int) Math.max(32, Math.round(srcW / (double) Math.max(srcH, srcW) * detLimit / 32.0) * 32);

    BufferedImage resized = ImageOps.resize(image, inW, inH);
    // PP-OCR detection normalize: (img/255 - mean) / std with ImageNet-ish stats.
    float[] input = ImageOps.toChwNormalized(resized, inH, inW, 3, DET_MEAN, DET_STD);
    long[] tensorShape = {1, channels, inH, inW};

    float[] prob;
    long[] outShape;
    try (OnnxTensor tensor =
            OnnxTensor.createTensor(env, FloatBuffer.wrap(input), tensorShape);
        OrtSession.Result result = detSession.run(Map.of(inputName, tensor))) {
      OnnxTensor out = (OnnxTensor) result.get(0).getValue();
      prob = new float[out.getFloatBuffer().remaining()];
      out.getFloatBuffer().get(prob);
      TensorInfo outInfo = (TensorInfo) result.get(0).getInfo();
      outShape = outInfo.getShape();
    }

    int ow = intDim(outShape, outShape.length - 1, inW);
    int oh = intDim(outShape, outShape.length - 2, inH);
    float scaleX = (float) srcW / ow;
    float scaleY = (float) srcH / oh;

    if (prob.length < ow * oh) {
      return List.of();
    }

    float[][] map = new float[oh][ow];
    for (int y = 0; y < oh; y++) {
      System.arraycopy(prob, y * ow, map[y], 0, ow);
    }
    List<int[]> boxes = db.boxes(map);
    for (int[] box : boxes) {
      box[0] = Math.round(box[0] * scaleX);
      box[1] = Math.round(box[1] * scaleY);
      box[2] = Math.round(box[2] * scaleX);
      box[3] = Math.round(box[3] * scaleY);
    }
    return boxes;
  }

  @Override
  public void close() throws Exception {
    if (detSession != null) detSession.close();
    if (recSession != null) recSession.close();
  }

  private static int intDim(long[] shape, int index, int fallback) {
    if (shape == null || index < 0 || index >= shape.length || shape[index] <= 0) {
      return fallback;
    }
    return (int) shape[index];
  }
}