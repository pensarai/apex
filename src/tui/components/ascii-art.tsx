import sharp from "sharp";
import React from "react";
import { RGBA } from "@opentui/core";

/**
 * ASCII character sets ordered by density (light to dark)
 */
export const ASCII_SETS = {
  simple: " .:-=+*#%@",
  detailed:
    " .'`^\",:;Il!i><~+_-?][}{1)(|\\/tfjrxnuvczXYUJCLQ0OZmwqpdbkhao*#MW&8%B@$",
  medium: " .,:;i1tfLCG08@",
  blocks: " ░▒▓█",
  default: " .:-=+*#%@",
} as const;

const ASCII_CHARS = ASCII_SETS.medium; // Using simpler set for clearer output

/**
 * Converts an image to ASCII art
 * @param path - Path to the image file
 * @param width - Desired width in characters
 * @param invert - Invert brightness (useful for dark backgrounds)
 * @returns Array of ASCII art strings, one per line
 */
export async function convertImageToAscii(
  path: string,
  width: number,
  invert: boolean = false
): Promise<string[]> {
  // Convert to grayscale and get pixel data
  const image = await sharp(path, {
    density: 300, // Higher DPI for better SVG rendering
  })
    .resize(width)
    .grayscale() // Convert to grayscale
    .raw()
    .toBuffer({ resolveWithObject: true });

  const { data, info } = image;
  const { width: w, height: h } = info;
  const lines: string[] = [];

  for (let y = 0; y < h; y++) {
    let line = "";
    for (let x = 0; x < w; x++) {
      const idx = y * w + x;
      let brightness = data[idx] ?? 0; // 0-255

      // Optionally invert for dark backgrounds
      if (invert) {
        brightness = 255 - brightness;
      }

      // Map brightness to ASCII character
      const charIndex = Math.floor(
        (brightness / 255) * (ASCII_CHARS.length - 1)
      );
      line += ASCII_CHARS[charIndex];
    }
    lines.push(line);
  }

  return lines;
}

/**
 * Converts an image to ASCII art with color
 * Scales the image by percentage first, then converts to ASCII
 *
 * @param input - Path to the image file or a Buffer containing image data
 * @param scale - Scale percentage (e.g., 0.5 = 50%, 1.0 = 100%, 2.0 = 200%)
 * @param maxWidth - Optional: maximum width in characters (if undefined, uses scaled size)
 * @param aspectRatio - Height adjustment factor (default: 0.5, since chars are ~2x taller than wide)
 * @param invert - Invert brightness for better contrast (default: false)
 * @returns 2D array of ASCII characters with RGB color data
 */
export async function convertImageToColoredAscii(
  input: string | Buffer,
  scale: number = 1.0,
  maxWidth?: number,
  aspectRatio: number = 0.5,
  invert: boolean = false
): Promise<{ char: string; r: number; g: number; b: number }[][]> {
  // First, get the original image dimensions
  const metadata = await sharp(input, { density: 300 }).metadata();
  const originalWidth = metadata.width ?? 100;
  const originalHeight = metadata.height ?? 100;

  // Calculate scaled dimensions
  let scaledWidth = Math.round(originalWidth * scale);
  let scaledHeight = Math.round(originalHeight * scale);

  // Adjust for terminal character aspect ratio (characters are ~2x taller than wide)
  // Apply the aspect ratio correction to prevent stretched appearance
  scaledHeight = Math.round(scaledHeight * aspectRatio);

  // Apply maxWidth constraint if specified
  if (maxWidth && scaledWidth > maxWidth) {
    const ratio = maxWidth / scaledWidth;
    scaledWidth = maxWidth;
    scaledHeight = Math.round(scaledHeight * ratio);
  }

  // Resize the image with sharp first
  // Use 'fill' to apply our custom aspect ratio, with kernel settings to reduce artifacts
  const resizeOptions = {
    width: scaledWidth,
    height: scaledHeight,
    fit: "fill" as const, // Use fill to apply our custom aspect ratio
    kernel: "lanczos3" as const, // High-quality downscaling kernel
    background: { r: 0, g: 0, b: 0, alpha: 0 }, // Transparent background
  };

  // Get color data with alpha channel
  const colorBuffer = await sharp(input, { density: 300 })
    .resize(resizeOptions)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  // Create grayscale from the already-resized color data to avoid double-resize artifacts
  const grayscaleBuffer = await sharp(colorBuffer.data, {
    raw: {
      width: colorBuffer.info.width,
      height: colorBuffer.info.height,
      channels: 4,
      premultiplied: false,
    },
  })
    .grayscale()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const { width: w, height: h } = grayscaleBuffer.info;
  const result: { char: string; r: number; g: number; b: number }[][] = [];

  for (let y = 0; y < h; y++) {
    const row: { char: string; r: number; g: number; b: number }[] = [];
    for (let x = 0; x < w; x++) {
      const grayIdx = y * w + x;
      const colorIdx = (y * w + x) * 4;

      const alpha = colorBuffer.data[colorIdx + 3] ?? 0;

      // If pixel is mostly transparent, use a space character
      if (alpha < 128) {
        row.push({
          char: " ",
          r: 0,
          g: 0,
          b: 0,
        });
        continue;
      }

      let brightness = grayscaleBuffer.data[grayIdx] ?? 0;

      // Invert brightness if requested (useful for dark images on light backgrounds)
      if (invert) {
        brightness = 255 - brightness;
      }

      const charIndex = Math.floor(
        (brightness / 255) * (ASCII_CHARS.length - 1)
      );

      row.push({
        char: ASCII_CHARS[charIndex] ?? " ",
        r: colorBuffer.data[colorIdx] ?? 0,
        g: colorBuffer.data[colorIdx + 1] ?? 0,
        b: colorBuffer.data[colorIdx + 2] ?? 0,
      });
    }
    result.push(row);
  }

  return result;
}

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
