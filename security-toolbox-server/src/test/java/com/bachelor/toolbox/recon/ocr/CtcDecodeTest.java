package com.bachelor.toolbox.recon.ocr;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class CtcDecodeTest {

  @Test
  void collapsesBlanksAndRepeats() {
    // dict holds the real characters; PaddleOCR remaps model index i -> dict[i-1].
    CtcDecode decode = new CtcDecode(List.of("甲", "乙"));
    // 3 timesteps, 3 vocab: argmax -> [1,1,2]; blank (0), 1 (repeat=skip), 2.
    float[] logits = new float[3 * 3];
    logits[1] = 0.9f; // index 1 -> dict[0] = 甲
    logits[4] = 0.8f; // index 1 again -> collapsed
    logits[8] = 0.7f; // index 2 -> dict[1] = 乙
    String text = decode.decode(logits, 3, 3);
    assertThat(text).isEqualTo("甲乙");
  }

  @Test
  void skipsTheBlankTokenAndOutOfVocabularyIndex() {
    CtcDecode decode = new CtcDecode(List.of("甲"));
    float[] logits = new float[3 * 3];
    logits[0] = 0.9f; // index 0 is blank -> skipped
    logits[2] = 0.9f; // index 2 maps beyond the 1-char dict -> dropped
    String text = decode.decode(logits, 1, 3);
    assertThat(text).isEqualTo("");
  }
}