#!/usr/bin/env bun

/**
 * Pre-generates ASCII art from pensar.svg at build time
 * This allows the compiled binary to work without sharp
 */

import { convertImageToColoredAscii } from "../src/tui/components/ascii-art";
import { writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const CONFIG = {
  scale: 1.0,
  maxWidth: 50,
  aspectRatio: 0.5,
  invert: true,
};

async function main() {
  const svgPath = join(__dirname, "..", "pensar.svg");
  
  console.log("Generating ASCII art from pensar.svg...");
  
  const coloredAscii = await convertImageToColoredAscii(
    svgPath,
    CONFIG.scale,
    CONFIG.maxWidth,
    CONFIG.aspectRatio,
    CONFIG.invert
  );
  
  const outputPath = join(__dirname, "..", "src", "tui", "generated-ascii-art.json");
  writeFileSync(outputPath, JSON.stringify(coloredAscii));
  
  console.log(`Generated ASCII art: ${coloredAscii.length} rows x ${coloredAscii[0]?.length || 0} columns`);
  console.log(`Saved to: ${outputPath}`);
}

main().catch(console.error);

