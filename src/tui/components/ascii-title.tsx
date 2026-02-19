import React, { useMemo } from "react";
import { RGBA } from "@opentui/core";
import { useTheme } from "../theme";

/**
 * Large ASCII art text for "APEX" with theme-derived gradient
 */

const APEX_ASCII = [
  "   █████████   ███████████  ██████████ █████ █████",
  "  ███░░░░░███ ░░███░░░░░███░░███░░░░░█░░███ ░░███ ",
  " ░███    ░███  ░███    ░███ ░███  █ ░  ░░███ ███  ",
  " ░███████████  ░██████████  ░██████     ░░█████   ",
  " ░███░░░░░███  ░███░░░░░░   ░███░░█      ███░███  ",
  " ░███    ░███  ░███         ░███ ░   █  ███ ░░███ ",
  " █████   █████ █████        ██████████ █████ █████",
  "░░░░░   ░░░░░ ░░░░░        ░░░░░░░░░░ ░░░░░ ░░░░░ ",
];

/**
 * Generate a gradient array from bright to dim based on a base RGBA color.
 * Goes from a boosted bright version (~160%) down to a dim version (~35%)
 * to match the original vibrant gradient range.
 */
function generateTitleGradient(base: RGBA, steps: number): RGBA[] {
  const r = base.r * 255;
  const g = base.g * 255;
  const b = base.b * 255;
  return Array.from({ length: steps }, (_, i) => {
    // t goes 0→1, gradient goes bright→dim (top of title is brightest)
    const t = steps === 1 ? 0 : i / (steps - 1);
    const brightness = 1.6 - t * 1.25;
    const warmShift = (1 - t) * 25;
    return RGBA.fromInts(
      Math.min(255, Math.round(r * brightness + warmShift)),
      Math.min(255, Math.round(g * brightness)),
      Math.min(255, Math.round(b * brightness + (1 - t) * 10)),
      255,
    );
  });
}

interface AsciiTitleProps {
  color?: RGBA;
}

export function AsciiTitle({ color }: AsciiTitleProps) {
  const { colors } = useTheme();
  const gradient = useMemo(
    () => generateTitleGradient(color || colors.primary, APEX_ASCII.length),
    [color, colors.primary],
  );

  return (
    <box flexDirection="column">
      {APEX_ASCII.map((row, idx) => (
        <text key={idx} fg={gradient[idx]}>
          {row}
        </text>
      ))}
    </box>
  );
}

/**
 * Subtitle component for "Apex CLI"
 */
export function AsciiSubtitle() {
  const { colors } = useTheme();

  // Smaller blocky text for "Apex CLI"
  const lines = ["█▀█ █▀█ █▀▀ ▀▄▀   █▀▀ █   █", "█▀█ █▀▀ ██▄ █ █   █▄▄ █▄▄ █"];

  return (
    <box flexDirection="column">
      {lines.map((line, idx) => (
        <text key={idx} fg={colors.text}>
          {line}
        </text>
      ))}
    </box>
  );
}
