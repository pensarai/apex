/**
 * Terminal Background Auto-Detection
 *
 * Uses the OSC 11 escape sequence to query the terminal's background color
 * and determine whether dark or light mode should be used.
 */

import type { ColorMode } from "./types";

/**
 * Detect the terminal's background color using the OSC 11 escape sequence.
 * Returns "dark" or "light" based on luminance calculation.
 * Falls back to "dark" if detection fails or times out.
 */
export async function detectTerminalMode(timeoutMs = 1000): Promise<ColorMode> {
  if (!process.stdin.isTTY) return "dark";

  return new Promise<ColorMode>((resolve) => {
    const timer = setTimeout(() => {
      cleanup();
      resolve("dark");
    }, timeoutMs);

    function cleanup() {
      clearTimeout(timer);
      process.stdin.removeListener("data", onData);
      process.stdin.setRawMode?.(false);
      process.stdin.pause();
    }

    function onData(data: Buffer) {
      const response = data.toString();
      // OSC 11 response format: \x1b]11;rgb:RRRR/GGGG/BBBB\x07
      const match = response.match(
        /\]11;rgb:([0-9a-f]+)\/([0-9a-f]+)\/([0-9a-f]+)/i,
      );
      if (match) {
        const [, rHex, gHex, bHex] = match;
        // Terminal returns 16-bit color values — use first 2 hex digits (8-bit)
        const r = parseInt(rHex.substring(0, 2), 16);
        const g = parseInt(gHex.substring(0, 2), 16);
        const b = parseInt(bHex.substring(0, 2), 16);
        // ITU-R BT.601 luminance
        const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
        cleanup();
        resolve(luminance > 0.5 ? "light" : "dark");
      }
    }

    process.stdin.setRawMode?.(true);
    process.stdin.resume();
    process.stdin.on("data", onData);
    // Send OSC 11 query: "what is the background color?"
    process.stdout.write("\x1b]11;?\x07");
  });
}
