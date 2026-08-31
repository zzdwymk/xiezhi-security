package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class MiitCaptchaSolverTest {

  @Test
  void refusesToSolveBlankChallenge() {
    assertThat(MiitCaptchaSolver.solve("", "small")).isNull();
    assertThat(MiitCaptchaSolver.solve("big", null)).isNull();
    assertThat(MiitCaptchaSolver.solve("  ", "small")).isNull();
  }

  @Test
  void refusesToGuessUntrainedPointChallenge() {
    // Without the ONNX detection/matching models the solver refuses to fabricate a guess so the
    // coordinator can surface a clear CAPTCHA_REQUIRED status and fall back to a manual source.
    assertThat(MiitCaptchaSolver.solve("big-image", "small-image")).isNull();
  }
}