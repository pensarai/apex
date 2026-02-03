import React from "react";
import { RGBA } from "@opentui/core";

/**
 * Large ASCII art text for "APEX" with green gradient
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

// Green gradient colors from bright (top) to dark (bottom)
const GREEN_GRADIENT = [
  { r: 144, g: 238, b: 144 }, // Light green
  { r: 124, g: 218, b: 124 },
  { r: 100, g: 200, b: 100 },
  { r: 76, g: 175, b: 80 },   // Medium green
  { r: 56, g: 155, b: 60 },
  { r: 46, g: 125, b: 50 },
  { r: 36, g: 100, b: 40 },
  { r: 27, g: 80, b: 33 },    // Dark green
];

interface AsciiTitleProps {
  color?: { r: number; g: number; b: number };
}

export function AsciiTitle({ color }: AsciiTitleProps) {
  return (
    <box flexDirection="column">
      {APEX_ASCII.map((row, idx) => {
        const gradientColor = color || GREEN_GRADIENT[idx] || GREEN_GRADIENT[GREEN_GRADIENT.length - 1];
        const rgbaColor = RGBA.fromInts(gradientColor.r, gradientColor.g, gradientColor.b, 255);
        return (
          <text key={idx} fg={rgbaColor}>
            {row}
          </text>
        );
      })}
    </box>
  );
}

/**
 * Subtitle component for "Apex CLI"
 */
export function AsciiSubtitle() {
  const color = RGBA.fromInts(255, 248, 220, 255);

  // Smaller blocky text for "Apex CLI"
  const lines = [
    "█▀█ █▀█ █▀▀ ▀▄▀   █▀▀ █   █",
    "█▀█ █▀▀ ██▄ █ █   █▄▄ █▄▄ █",
  ];

  return (
    <box flexDirection="column">
      {lines.map((line, idx) => (
        <text key={idx} fg={color}>
          {line}
        </text>
      ))}
    </box>
  );
}
