import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const techniquesDir = dirname(fileURLToPath(import.meta.url));

/**
 * Load a technique file by name (without extension).
 * Reads `src/core/techniques/{name}.md` and returns its content as a string.
 */
export function loadTechnique(name: string): string {
  const filePath = join(techniquesDir, `${name}.md`);
  return readFileSync(filePath, "utf-8");
}
