package com.bachelor.toolbox.recon.ocr;

import static org.assertj.core.api.Assertions.assertThat;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CtcDictionarySpaceTests {
  @TempDir Path temporary;

  @Test
  void appendsThePaddleSpaceClassWithoutDroppingInteriorSpaces() throws Exception {
    Path dict = temporary.resolve("dict.txt");
    Files.writeString(dict, "A\nB\n");
    CtcDecode decoder = CtcDecode.fromDictFile(dict);
    float[] logits = {0,1,0,0, 0,0,0,1, 0,0,1,0};
    assertThat(decoder.decode(logits, 3, 4)).isEqualTo("A B");
  }

  @Test
  void doesNotDuplicateAnAlreadyPresentSpaceClass() throws Exception {
    Path dict = temporary.resolve("dict-with-space.txt");
    Files.writeString(dict, "A\n \n");
    CtcDecode decoder = CtcDecode.fromDictFile(dict);
    assertThat(decoder.decode(new float[] {0,0,1}, 1, 3)).isEqualTo(" ");
    assertThat(decoder.decode(new float[] {0,0,0,1}, 1, 4)).isEmpty();
  }
}
