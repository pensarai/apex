/**
 * Loader Demo — run with `bun loader-demo.tsx`
 *
 * Standalone screen that renders every loader from loaders.tsx
 * so you can preview them in the terminal.
 */

import { createRoot } from "@opentui/react";
import { createCliRenderer, RGBA } from "@opentui/core";
import { ThemeProvider, resolveThemeColors, getTheme } from "./src/tui/theme";
import { registerBuiltinThemes } from "./src/tui/theme/themes";
import { TerminalDimensionsProvider } from "./src/tui/context/dimensions";
import {
  SpinningDots,
  BouncingBox,
  BracketBounce,
  PulseRing,
  WaveBar,
  BarPulse,
  OrbitDots,
  ScanLine,
  Typewriter,
  LaserBar,
  ShiningText,
} from "./src/tui/components/loaders";
import { useTheme } from "./src/tui/theme";
import { detectTerminalMode } from "./src/tui/theme/detect-mode";
import { buildConsoleOptions, ConsoleThemeSync } from "./src/tui/console-theme";
import { useKeyboard } from "@opentui/react";

function Demo() {
  const { colors } = useTheme();

  useKeyboard((key) => {
    if (
      key.name === "escape" ||
      key.name === "q" ||
      (key.ctrl && key.name === "c")
    ) {
      process.exit(0);
    }
  });

  const cyan = RGBA.fromInts(0, 200, 220, 255);
  const magenta = RGBA.fromInts(200, 80, 220, 255);
  const amber = RGBA.fromInts(240, 180, 40, 255);
  const red = RGBA.fromInts(255, 60, 60, 255);

  return (
    <box flexDirection="column" padding={2} gap={1}>
      <text fg={colors.text}>Loader Demo — press q or Esc to exit</text>
      <text fg={colors.textMuted} content={"─".repeat(50)} />

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>SpinningDots — default</text>
        <SpinningDots />
        <text fg={colors.textMuted}>SpinningDots — fast</text>
        <SpinningDots intervalMs={30} />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>BouncingBox — default (w=24)</text>
        <BouncingBox />
        <text fg={colors.textMuted}>BouncingBox — wide / amber</text>
        <BouncingBox width={40} fg={amber} speed={1} />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>BracketBounce — fast</text>
        <BracketBounce speed={1} />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>PulseRing — default</text>
        <PulseRing />
        <text fg={colors.textMuted}>PulseRing — fast / cyan</text>
        <PulseRing fg={cyan} speed={2} />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>WaveBar — default</text>
        <WaveBar />
        <text fg={colors.textMuted}>WaveBar — bounce</text>
        <WaveBar bounce />
        <text fg={colors.textMuted}>WaveBar — amber wide / bounce</text>
        <WaveBar width={32} fg={amber} speed={2} bounce />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>BarPulse — default</text>
        <BarPulse />
        <text fg={colors.textMuted}>BarPulse — wide / magenta</text>
        <BarPulse bars={16} fg={magenta} />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>ScanLine — default</text>
        <ScanLine />
        <text fg={colors.textMuted}>ScanLine — bounce</text>
        <ScanLine bounce />
        <text fg={colors.textMuted}>ScanLine — wide / cyan / bounce</text>
        <ScanLine width={40} fg={cyan} speed={1} bounce />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>OrbitDots — default</text>
        <OrbitDots />
        <text fg={colors.textMuted}>OrbitDots — 5 dots / amber</text>
        <OrbitDots count={5} fg={amber} />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>LaserBar</text>
        <LaserBar />
        <text fg={colors.textMuted}>LaserBar — brackets</text>
        <LaserBar brackets />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>ShiningText — default</text>
        <ShiningText text="PENSAR APEX" />
        <text fg={colors.textMuted}>ShiningText — wide shimmer / cyan</text>
        <ShiningText text="Initializing scan..." fg={cyan} shimmerWidth={8} />
      </box>

      <box flexDirection="column" gap={0}>
        <text fg={colors.textMuted}>Typewriter — default</text>
        <Typewriter text="Establishing connection..." />
        <text fg={colors.textMuted}>Typewriter — fast / red</text>
        <Typewriter text="ALERT: intrusion detected" fg={red} speed={2} />
      </box>
    </box>
  );
}

async function main() {
  registerBuiltinThemes();
  const mode = await detectTerminalMode();
  const themeColors = resolveThemeColors(getTheme("apex"), mode);

  const renderer = await createCliRenderer({
    exitOnCtrlC: true,
    consoleOptions: buildConsoleOptions(themeColors),
  });

  const cleanup = () => {
    renderer.destroy();
    process.exit(0);
  };
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);

  createRoot(renderer).render(
    <ThemeProvider initialTheme="apex" initialMode={mode}>
      <ConsoleThemeSync />
      <TerminalDimensionsProvider>
        <Demo />
      </TerminalDimensionsProvider>
    </ThemeProvider>,
  );
}

main();
