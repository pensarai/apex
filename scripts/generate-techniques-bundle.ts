#!/usr/bin/env bun

/**
 * Pre-generates a JSON bundle of all technique SKILL.md files at build time.
 * This allows the compiled binary to work without filesystem access to the
 * techniques directory (bun --compile resolves import.meta.url to /$bunfs/root).
 */

import { readFileSync, readdirSync, statSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const techniquesDir = join(__dirname, "..", "src", "core", "techniques");
const outputPath = join(techniquesDir, "generated-techniques-bundle.json");

interface BundledTechnique {
  name: string;
  content: string;
}

function main() {
  const techniques: BundledTechnique[] = [];
  const entries = readdirSync(techniquesDir);

  for (const entry of entries) {
    const entryPath = join(techniquesDir, entry);
    if (!statSync(entryPath).isDirectory()) continue;

    const skillPath = join(entryPath, "SKILL.md");
    try {
      const content = readFileSync(skillPath, "utf-8");
      techniques.push({ name: entry, content });
    } catch {
      // Skip directories without SKILL.md
    }
  }

  writeFileSync(outputPath, JSON.stringify(techniques, null, 2));
  console.log(
    `Bundled ${techniques.length} techniques: ${techniques.map((t) => t.name).join(", ")}`,
  );
  console.log(`Saved to: ${outputPath}`);
}

main();
