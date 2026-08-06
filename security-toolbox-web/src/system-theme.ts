function normalizeAccent(value: string | undefined) {
  return /^#[0-9a-f]{6}$/i.test(value || "") ? value! : "#0078d4";
}

/**
 * Return the WCAG relative luminance for a six-digit sRGB color.
 *
 * The previous implementation used a fixed luminance cut-off (.46).  That
 * cut-off is much too high: a number of medium-light accents get white text
 * even though dark text has the better (and sometimes the only acceptable)
 * contrast.  Keeping the calculation here, next to the system-theme bridge,
 * also means the value used by CSS is updated whenever Windows changes its
 * accent color.
 */
function relativeLuminance(hex: string) {
  const value = hex.slice(1);
  const red = Number.parseInt(value.slice(0, 2), 16) / 255;
  const green = Number.parseInt(value.slice(2, 4), 16) / 255;
  const blue = Number.parseInt(value.slice(4, 6), 16) / 255;
  const linear = (channel: number) =>
    channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  return 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue);
}

function contrastRatio(luminanceA: number, luminanceB: number) {
  const lighter = Math.max(luminanceA, luminanceB);
  const darker = Math.min(luminanceA, luminanceB);
  return (lighter + 0.05) / (darker + 0.05);
}

function contrastColor(hex: string) {
  const backgroundLuminance = relativeLuminance(hex);
  const darkForeground = "#111111";
  const lightForeground = "#ffffff";
  const darkContrast = contrastRatio(
    relativeLuminance(darkForeground),
    backgroundLuminance,
  );
  const lightContrast = contrastRatio(
    relativeLuminance(lightForeground),
    backgroundLuminance,
  );

  // Select whichever of the two supported foreground tokens has the higher
  // contrast.  This is equivalent to the WCAG crossover near L=0.18, but
  // comparing the actual candidate colors also accounts for #111111 rather
  // than assuming a pure black foreground.
  return darkContrast >= lightContrast ? darkForeground : lightForeground;
}

function applySystemTheme(theme: SystemThemeState) {
  const accent = normalizeAccent(theme.accentColor);
  const caption = normalizeAccent(theme.captionColor);
  const themeAccent = accent;
  const root = document.documentElement;
  root.style.setProperty("--system-accent", accent);
  root.style.setProperty("--system-caption-color", caption);
  root.style.setProperty("--system-theme-accent", themeAccent);
  root.style.setProperty(
    "--system-accent-foreground",
    contrastColor(themeAccent),
  );
  const chromeSurface =
    !theme.transparencyEnabled ||
    theme.highContrast ||
    theme.windowMaterial === "none"
      ? theme.dark
        ? "#202020"
        : "#f3f3f3"
      : theme.windowMaterial === "acrylic"
        ? "color-mix(in srgb, Canvas 14%, transparent)"
        : "transparent";
  root.style.setProperty("--shared-chrome-surface", chromeSurface);
  root.style.colorScheme = theme.dark ? "dark" : "light";
  root.dataset.systemTheme = theme.dark ? "dark" : "light";
  root.dataset.captionMode = theme.captionMode;
  root.dataset.windowMaterial =
    theme.windowMaterial || (theme.captionMode === "mica" ? "mica" : "none");
  root.dataset.autoColorization = theme.autoColorization ? "true" : "false";
  root.dataset.transparency = theme.transparencyEnabled ? "true" : "false";
  root.dataset.highContrast = theme.highContrast ? "true" : "false";
}

export async function initializeSystemTheme() {
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const fallback = () =>
    applySystemTheme({
      accentColor: "#0078d4",
      captionColor: "#0078d4",
      captionMode: "solid",
      useAccentOnTitleBars: false,
      forcedCaptionAccent: false,
      transparencyEnabled: false,
      autoColorization: false,
      appsUseLightTheme: !media.matches,
      systemUsesLightTheme: !media.matches,
      dark: media.matches,
      highContrast: window.matchMedia("(forced-colors: active)").matches,
    });

  fallback();
  const bridge = window.toolboxDesktop;
  if (!bridge?.getSystemTheme) return;

  try {
    applySystemTheme(await bridge.getSystemTheme());
  } catch {
    fallback();
  }
  bridge.onSystemThemeChanged?.(applySystemTheme);
}
