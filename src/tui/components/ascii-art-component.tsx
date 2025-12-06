import React from "react";
import { RGBA } from "@opentui/core";

/**
 * Props for the ColoredAsciiArt component
 */
export interface ColoredAsciiArtProps {
  ascii: { char: string; r: number; g: number; b: number }[][];
  /**
   * Optional title to display above the ASCII art
   */
  title?: string;
}

/**
 * Standalone component for rendering colored ASCII art
 * Handles the mapping and rendering of ASCII characters with colors
 *
 * Note: This file is separate from ascii-art.tsx to avoid bundling sharp
 * in the compiled binary. The ascii-art.tsx file uses sharp for generation,
 * but this component only handles display.
 */
export function ColoredAsciiArt({ ascii, title }: ColoredAsciiArtProps) {
  return (
    <box
      position="absolute"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      height="100%"
      width="100%"
      flexGrow={1}
    >
      {title && <text>{title}</text>}
      {ascii.map((row, y) => (
        <text key={y}>
          {row.map((pixel, x) => {
            const color = RGBA.fromInts(pixel.r, pixel.g, pixel.b, 50);
            return (
              <span key={x} fg={color}>
                {pixel.char}
              </span>
            );
          })}
        </text>
      ))}
    </box>
  );
}
