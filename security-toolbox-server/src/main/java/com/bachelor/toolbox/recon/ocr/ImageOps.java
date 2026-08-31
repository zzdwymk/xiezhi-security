package com.bachelor.toolbox.recon.ocr;

import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import javax.imageio.ImageIO;

/** Small image helpers used to feed PaddleOCR det/rec heads with CHW float tensors. */
final class ImageOps {

  private ImageOps() {}

  static BufferedImage fromBase64(String base64) throws Exception {
    byte[] bytes = Base64.getDecoder().decode(base64);
    ByteArrayInputStream in = new ByteArrayInputStream(bytes);
    BufferedImage image = ImageIO.read(in);
    if (image == null) {
      throw new IllegalArgumentException("无法解码验证码图片");
    }
    return image;
  }

  /** Scales the image to the given width/height with high-quality rendering. */
  static BufferedImage resize(BufferedImage source, int width, int height) {
    BufferedImage target =
        new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
    Graphics2D g = target.createGraphics();
    g.setRenderingHint(
        RenderingHints.KEY_INTERPOLATION,
        RenderingHints.VALUE_INTERPOLATION_BILINEAR);
    g.drawImage(source, 0, 0, width, height, null);
    g.dispose();
    return target;
  }

  static BufferedImage toRgb(BufferedImage image) {
    if (image.getType() == BufferedImage.TYPE_INT_RGB) {
      return image;
    }
    BufferedImage rgb =
        new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_RGB);
    Graphics2D g = rgb.createGraphics();
    g.drawImage(image, 0, 0, null);
    g.dispose();
    return rgb;
  }

  /** Returns a normalized CxHxW float tensor: (pixel/255 - mean)/std, channel-major. */
  static float[] toChwNormalized(BufferedImage image, int h, int w, int channels, float[] mean, float[] std) {
    BufferedImage rgb = toRgb(image);
    float[] out = new float[3 * h * w];
    for (int y = 0; y < h; y++) {
      for (int x = 0; x < w; x++) {
        int argb = rgb.getRGB(x, y);
        float r = (((argb >> 16) & 0xFF) / 255.0f - mean[0]) / std[0];
        float g = (((argb >> 8) & 0xFF) / 255.0f - mean[1]) / std[1];
        float b = ((argb & 0xFF) / 255.0f - mean[2]) / std[2];
        out[0 * h * w + y * w + x] = r;
        out[1 * h * w + y * w + x] = g;
        out[2 * h * w + y * w + x] = b;
      }
    }
    return out;
  }

  /**
   * Returns a normalized CxHxW float tensor for a PaddleOCR det/rec input (channel-major, values
   * 0..1). If {@code channels} is 1, only the green channel is used (closest to a plain grayscale
   * ODRCNet) but for robustness we always deliver 3 channels by default.
   */
  static float[] toChw(BufferedImage image, int h, int w, int channels) {
    BufferedImage rgb = toRgb(image);
    int finalChannels = channels;
    if (finalChannels == 1) {
      finalChannels = 3;
    }
    float[] out = new float[finalChannels * h * w];
    for (int y = 0; y < h; y++) {
      for (int x = 0; x < w; x++) {
        int argb = rgb.getRGB(x, y);
        float r = ((argb >> 16) & 0xFF) / 255.0f;
        float g = ((argb >> 8) & 0xFF) / 255.0f;
        float b = (argb & 0xFF) / 255.0f;
        out[0 * h * w + y * w + x] = r;
        out[1 * h * w + y * w + x] = g;
        out[2 * h * w + y * w + x] = b;
      }
    }
    return out;
  }
}