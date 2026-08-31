package com.bachelor.toolbox.recon.ocr;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * CTC collapsed decoding for PaddleOCR recognition heads. The recognition model emits a
 * probability tensor of shape {@code [1, timesteps, vocab]}; this class argmax-decodes it,
 * removes blanks and consecutive duplicates, then maps indices to the PaddleOCR character
 * dictionary (supplied as {@code ppocr_keys_v1.txt}).
 */
final class CtcDecode {

  private final List<String> vocabulary;

  CtcDecode(List<String> vocabulary) {
    this.vocabulary = vocabulary;
  }

  static CtcDecode fromDictFile(Path path) throws Exception {
    List<String> words = new ArrayList<>();
    byte[] bytes = Files.readAllBytes(path);
    String content = new String(bytes, StandardCharsets.UTF_8);
    // PaddleOCR dict files separate characters by newlines; the blank token is index 0.
    content = content.replace("\r", "");
    for (String line : content.split("\n")) {
      words.add(line);
    }
    return new CtcDecode(words);
  }

  /**
   * @param logits shape [timesteps][vocabSize] flattened probabilities; caller supplies
   *      the 1 x T x C tensor as a plain float array of length timesteps * vocab.
   */
  String decode(float[] logits, int timesteps, int vocabSize) {
    StringBuilder text = new StringBuilder();
    int prev = 0; // blank is index 0
    for (int t = 0; t < timesteps; t++) {
      int argmax = maxIndex(logits, t, vocabSize);
      if (argmax != 0 && argmax != prev) {
        if (argmax < vocabulary.size()) {
          text.append(vocabulary.get(argmax));
        }
      }
      prev = argmax;
    }
    return text.toString();
  }

  private static int maxIndex(float[] data, int t, int vocab) {
    int best = 0;
    float bestScore = Float.NEGATIVE_INFINITY;
    int base = t * vocab;
    for (int c = 0; c < vocab; c++) {
      float value = data[base + c];
      if (value > bestScore) {
        bestScore = value;
        best = c;
      }
    }
    return best;
  }
}