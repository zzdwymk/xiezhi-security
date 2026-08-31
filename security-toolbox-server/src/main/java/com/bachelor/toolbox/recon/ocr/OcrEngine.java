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
  private final CtcDecode ctc;

  private OcrEngine(
      OrtEnvironment env, OrtSession detSession, OrtSession recSession, CtcDecode ctc) {
    this.env = env;
    this.detSession = detSession;
    this.recSession = recSession;
    this.db = new DbPostProcess();
    this.ctc = ctc;
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
      CtcDecode ctc = CtcDecode.fromDictFile(dict);
      OrtEnvironment env = OrtEnvironment.getEnvironment();
      return new OcrEngine(
          env, env.createSession(det.toString()), env.createSession(rec.toString()), ctc);
    } catch (Exception exception) {
      return null;
    }
  }

  public boolean available() {
    return detSession != null && recSession != null;
  }

  /**
   * Resolves the point challenge from just the big background image, using every detected text box
   * as a candidate click target. Prefer {@link #solve(String, String)} which also matches the
   * character strip so the points come back in the requested order.
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
      return toPoints(boxes, null, big);
    } catch (Exception exception) {
      return null;
    }
  }

  /**
   * Solves the "click the characters" challenge.
   *
   * <p>The strip (small) image shows the characters to click, in order. Each detected text box in
   * the big image is recognized and the click points come back centered on the boxes that match
   * the strip characters. Returns {@code null} when the challenge cannot be resolved confidently.
   *
   * @param bigImage base64 background image that contains scattered characters
   * @param smallImage base64 strip image showing the characters to click, in order
   * @return the ordered click points (image coordinates, centered on each matched character)
   */
  public List<Map<String, Object>> solve(String bigImage, String smallImage) {
    if (!available()) {
      return null;
    }
    try {
      BufferedImage big =
          bigImage == null || bigImage.isBlank() ? null : ImageOps.fromBase64(bigImage);
      BufferedImage strip =
          smallImage == null || smallImage.isBlank() ? null : ImageOps.fromBase64(smallImage);
      if (big == null) {
        return null;
      }
      List<int[]> bigBoxes = detect(big);
      if (bigBoxes.isEmpty()) {
        return null;
      }
      List<Map<String, Object>> resolved = toPoints(bigBoxes, strip, big);
      return resolved;
    } catch (Exception exception) {
      return null;
    }
  }

  /** Recognized text box: bounding box plus the character string produced by the rec model. */
  private static final class BoxText {
    final int[] box;
    final String text;

    BoxText(int[] box, String text) {
      this.box = box;
      this.text = text;
    }
  }

  private List<Map<String, Object>> toPoints(List<int[]> bigBoxes, BufferedImage strip,
      BufferedImage big) throws Exception {
    List<BoxText> candidates = new ArrayList<>();
    for (int[] box : bigBoxes) {
      candidates.add(new BoxText(box, recognize(big, box)));
    }

    if (strip == null) {
      // No strip: return all detected points so a caller can still show/probe them (no matching).
      List<Map<String, Object>> out = new ArrayList<>();
      for (BoxText c : candidates) {
        out.add(point(c.box));
      }
      return out.isEmpty() ? null : out;
    }

    List<String> required = stripChars(strip);
    if (required.isEmpty()) {
      return null;
    }
    List<Map<String, Object>> out = new ArrayList<>();
    for (String want : required) {
      boolean found = false;
      for (BoxText c : candidates) {
        if (want.equals(c.text)) {
          out.add(point(c.box));
          found = true;
          break;
        }
      }
      if (!found) {
        // A requested character could not be located; do not risk a wrong click.
        return null;
      }
    }
    return out.isEmpty() ? null : out;
  }

  /** Centers a click point on a detected box. */
  private static Map<String, Object> point(int[] box) {
    Map<String, Object> p = new LinkedHashMap<>();
    int cx = box[0] + (box[2] - box[0]) / 2;
    int cy = box[1] + (box[3] - box[1]) / 2;
    p.put("x", cx);
    p.put("y", cy);
    return p;
  }

  /** Recognizes each sub-box of the strip image and returns the character strings, left to right. */
  private List<String> stripChars(BufferedImage strip) throws Exception {
    List<int[]> boxes = detect(strip);
    if (boxes.isEmpty()) {
      return List.of();
    }
    // DB detection can over-segment a single character into several small fragments; merge any
    // boxes that horizontally touch or sit right next to each other so each strip character is
    // recognized as one region.
    List<int[]> merged = mergeBoxes(boxes);
    merged.sort((a, b) -> Integer.compare(a[0], b[0]));
    List<String> texts = new ArrayList<>();
    for (int[] box : merged) {
      String t = recognize(strip, box);
      if (t != null && !t.isBlank()) {
        texts.add(t);
      }
    }
    return texts;
  }

  /**
   * Greedily merges horizontally-adjacent/overlapping boxes into a single box. Boxes whose
   * x-spans touch (gap &le; half the box height) and whose y-spans overlap are unioned.
   */
  private static List<int[]> mergeBoxes(List<int[]> boxes) {
    List<int[]> sorted = new ArrayList<>(boxes);
    sorted.sort((a, b) -> Integer.compare(a[0], b[0]));
    List<int[]> out = new ArrayList<>();
    for (int[] b : sorted) {
      if (out.isEmpty()) {
        out.add(b.clone());
        continue;
      }
      int[] last = out.get(out.size() - 1);
      int gap = b[0] - last[2];
      int maxHeight = Math.max(last[3] - last[1], b[3] - b[1]);
      boolean yOverlap = b[1] < last[3] && last[1] < b[3];
      if (yOverlap && gap <= Math.max(1, maxHeight / 2)) {
        last[2] = Math.max(last[2], b[2]);
        last[3] = Math.max(last[3], b[3]);
        last[1] = Math.min(last[1], b[1]);
      } else {
        out.add(b.clone());
      }
    }
    return out;
  }

  /** Runs the PP-OCR recognition head on the given sub-image box and returns the decoded text. */
  private String recognize(BufferedImage image, int[] box) throws Exception {
    int x0 = Math.max(0, box[0] - 2);
    int y0 = Math.max(0, box[1] - 2);
    int x1 = Math.min(image.getWidth(), box[2] + 2);
    int y1 = Math.min(image.getHeight(), box[3] + 2);
    if (x1 <= x0 || y1 <= y0) {
      return "";
    }
    BufferedImage crop = image.getSubimage(x0, y0, x1 - x0, y1 - y0);

    // PP-OCR rec expects a fixed height (48 here); recompute width to preserve the box aspect ratio.
    int recH = 48;
    int recW = Math.max(10, Math.round((float) (x1 - x0) * recH / (y1 - y0)));
    BufferedImage resized = ImageOps.resize(crop, recW, recH);
    // PaddleOCR rec normalizes to 0..1 (mean = std = 0.5).
    float[] input = ImageOps.toChw(resized, recH, recW, 3);

    String inputName = new ArrayList<>(recSession.getInputInfo().keySet()).get(0);
    long[] shape = {1, 3, recH, recW};
    float[] logits;
    long[] outShape;
    try (OnnxTensor tensor = OnnxTensor.createTensor(env, FloatBuffer.wrap(input), shape);
        OrtSession.Result result = recSession.run(Map.of(inputName, tensor))) {
      OnnxTensor out = (OnnxTensor) result.get(0);
      TensorInfo oi = (TensorInfo) result.get(0).getInfo();
      logits = new float[out.getFloatBuffer().remaining()];
      out.getFloatBuffer().get(logits);
      outShape = oi.getShape();
    }
    // Output is [1, T, vocab]; decode the flattened logits with the CTC decoder.
    long vocab = outShape[outShape.length - 1];
    long timesteps = outShape[outShape.length - 2];
    if (timesteps * vocab <= 0 || logits.length < timesteps * vocab) {
      return "";
    }
    String text = ctc.decode(logits, (int) timesteps, (int) vocab);
    return text == null ? "" : text.trim();
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
      OnnxTensor out = (OnnxTensor) result.get(0);
      TensorInfo outInfo = (TensorInfo) result.get(0).getInfo();
      prob = new float[out.getFloatBuffer().remaining()];
      out.getFloatBuffer().get(prob);
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