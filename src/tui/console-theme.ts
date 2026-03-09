import { useEffect } from "react";
import { useRenderer } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { useTheme, type ThemeColors } from "./theme";

export const withAlpha = (rgba: RGBA, a: number) =>
  RGBA.fromValues(rgba.r, rgba.g, rgba.b, a);

/**
 * Mutable ref for non-React code (post-process overlays) to read current
 * theme colors. Updated by ConsoleThemeSync on every theme change.
 */
export const overlayThemeRef: { current: ThemeColors | null } = {
  current: null,
};

/** Build the initial consoleOptions for createCliRenderer. */
export function buildConsoleOptions(themeColors: ThemeColors) {
  return {
    backgroundColor: withAlpha(themeColors.backgroundPanel, 0.85),
    titleBarColor: withAlpha(themeColors.backgroundElement, 0.9),
    titleBarTextColor: themeColors.text,
    colorDefault: themeColors.textMuted,
    colorInfo: themeColors.info,
    colorWarn: themeColors.warning,
    colorError: themeColors.error,
    colorDebug: themeColors.textMuted,
    selectionColor: withAlpha(themeColors.primary, 0.35),
    cursorColor: themeColors.primary,
    copyButtonColor: themeColors.primary,
  };
}

/**
 * React component that syncs the active theme to the console pane and
 * the overlay theme ref. Renders nothing — purely a side-effect component.
 */
export function ConsoleThemeSync() {
  const { colors } = useTheme();
  const renderer = useRenderer();
  useEffect(() => {
    overlayThemeRef.current = colors;
    // Keep console colors in sync with the active theme
    const c = renderer.console as any;
    c.backgroundColor = withAlpha(colors.backgroundPanel, 0.85);
    c._rgbaTitleBar = withAlpha(colors.backgroundElement, 0.9);
    c._rgbaTitleBarText = colors.text;
    c._rgbaDefault = colors.textMuted;
    c._rgbaInfo = colors.info;
    c._rgbaWarn = colors.warning;
    c._rgbaError = colors.error;
    c._rgbaDebug = colors.textMuted;
    c._rgbaSelection = withAlpha(colors.primary, 0.35);
    c._rgbaCursor = colors.primary;
    c._rgbaCopyButton = colors.primary;
    c.markNeedsRerender();
  }, [colors]);
  return null;
}
