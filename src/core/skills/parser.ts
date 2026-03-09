import { parse as parseYaml } from "yaml";
import type { SkillManifest } from "./types";

/**
 * Split raw markdown into frontmatter block and body.
 * Returns null if no valid `---` delimiters are found.
 */
function splitFrontmatter(raw: string): {
  block: string;
  body: string;
} | null {
  const trimmed = raw.trimStart();
  if (!trimmed.startsWith("---")) return null;

  const endIdx = trimmed.indexOf("---", 3);
  if (endIdx === -1) return null;

  return {
    block: trimmed.slice(3, endIdx).trim(),
    body: trimmed.slice(endIdx + 3).trim(),
  };
}

/**
 * Parse a skills.sh-compatible SKILL.md file.
 *
 * Expects YAML frontmatter delimited by `---`, followed by markdown body.
 * Uses the `yaml` package for robust parsing (arrays, nested objects).
 */
export function parseSkillMd(raw: string): {
  manifest: SkillManifest;
  instructions: string;
} {
  const trimmed = raw.trimStart();
  if (!trimmed.startsWith("---")) {
    throw new Error("SKILL.md missing YAML frontmatter (no opening ---)");
  }
  const parts = splitFrontmatter(raw);
  if (!parts) {
    throw new Error("SKILL.md missing closing --- delimiter");
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = parseYaml(parts.block) as Record<string, unknown>;
  } catch (err) {
    throw new Error(
      `SKILL.md frontmatter YAML parse error: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (!parsed || typeof parsed !== "object") {
    throw new Error("SKILL.md frontmatter is not an object");
  }

  const name = parsed.name;
  const description = parsed.description;

  if (typeof name !== "string" || !name.trim()) {
    throw new Error("SKILL.md missing required field: name");
  }
  if (typeof description !== "string" || !description.trim()) {
    throw new Error("SKILL.md missing required field: description");
  }

  const manifest: SkillManifest = {
    name: name.trim(),
    description: description.trim(),
  };

  if (typeof parsed.version === "string") {
    manifest.version = parsed.version;
  }
  if (Array.isArray(parsed.tags)) {
    manifest.tags = parsed.tags.filter(
      (t): t is string => typeof t === "string",
    );
  }
  if (Array.isArray(parsed.triggers)) {
    manifest.triggers = parsed.triggers.filter(
      (t): t is string => typeof t === "string",
    );
  }
  if (Array.isArray(parsed.inputs)) {
    manifest.inputs = parsed.inputs
      .filter((i): i is Record<string, unknown> => i && typeof i === "object")
      .map((i) => ({
        name: String(i.name ?? ""),
        description:
          typeof i.description === "string" ? i.description : undefined,
        required: typeof i.required === "boolean" ? i.required : undefined,
      }));
  }
  if (Array.isArray(parsed.outputs)) {
    manifest.outputs = parsed.outputs
      .filter((o): o is Record<string, unknown> => o && typeof o === "object")
      .map((o) => ({
        name: String(o.name ?? ""),
        description:
          typeof o.description === "string" ? o.description : undefined,
      }));
  }

  return { manifest, instructions: parts.body };
}

/**
 * Parse a legacy flat-file skill (.md with simple key: value frontmatter).
 */
export function parseLegacySkillMd(raw: string): {
  name: string;
  description: string;
  content: string;
} {
  const parts = splitFrontmatter(raw);
  if (!parts) {
    return { name: "", description: "", content: raw };
  }

  const meta: Record<string, string> = {};
  for (const line of parts.block.split("\n")) {
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim();
    const value = line.slice(colonIdx + 1).trim();
    meta[key] = value;
  }

  return {
    name: meta.name ?? "",
    description: meta.description ?? "",
    content: parts.body,
  };
}
