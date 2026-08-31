package com.bachelor.toolbox.recon.ocr;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class CtcDecodeTest {

  @Test
  void collapsesBlanksAndRepeats() {
    // dict = [_, A, B]; blank is index 0.
    CtcDecode decode = new CtcDecode(List.of("", "甲", "乙"));
    // 3 timesteps, 3 vocab: argmax -> [1,1,2] with a blank at 0 then 1 then 2.
    float[] logits = new float[3 * 3];
    logits[1] = 0.9f;
    logits[4] = 0.8f;
    logits[8] = 0.7f;
    String text = decode.decode(logits, 3, 3);
    assertThat(text).isEqualTo("甲乙");
  }

  @Test
  void ignoresOutOfVocabularyIndex() {
    CtcDecode decode = new CtcDecode(List.of("甲"));
    float[] logits = new float[3 * 3];
    logits[2] = 0.9f; // index 2 maps to vocab[1], beyond size
    String text = decode.decode(logits, 1, 3);
    assertThat(text).isEqualTo("");
  }
}