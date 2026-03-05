import { readFileSync, readdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const techniquesDir = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TechniqueMetadata {
  /** Unique identifier (directory name) */
  name: string;
  /** Description used by agents to decide whether to load this technique */
  description: string;
}

// ---------------------------------------------------------------------------
// Frontmatter parsing
// ---------------------------------------------------------------------------

/**
 * Parse YAML frontmatter from a SKILL.md file.
 * Extracts `name` and `description` from the `---` delimited header.
 */
function parseFrontmatter(content: string): {
  metadata: { name: string; description: string };
  body: string;
} {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
  if (!match) {
    throw new Error("SKILL.md missing YAML frontmatter (---) delimiters");
  }

  const [, yaml, body] = match;

  // Simple YAML extraction — handles both inline and multiline (>) values
  const nameMatch = yaml.match(/^name:\s*(.+)$/m);
  const name = nameMatch?.[1]?.trim() ?? "";

  // Description can be multiline with > continuation
  let description = "";
  const descMatch = yaml.match(/^description:\s*>?\s*\n?([\s\S]*?)(?=\n\w|\n---|\s*$)/m);
  if (descMatch) {
    description = descMatch[1]
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .join(" ");
  } else {
    const inlineDesc = yaml.match(/^description:\s*(.+)$/m);
    description = inlineDesc?.[1]?.trim() ?? "";
  }

  return { metadata: { name, description }, body: body.trim() };
}

// ---------------------------------------------------------------------------
// Technique discovery (cached)
// ---------------------------------------------------------------------------

let _catalog: TechniqueMetadata[] | null = null;
let _bodies: Map<string, string> | null = null;

function ensureLoaded(): void {
  if (_catalog) return;

  _catalog = [];
  _bodies = new Map();

  const entries = readdirSync(techniquesDir);

  for (const entry of entries) {
    const entryPath = join(techniquesDir, entry);
    if (!statSync(entryPath).isDirectory()) continue;

    const skillPath = join(entryPath, "SKILL.md");
    try {
      const content = readFileSync(skillPath, "utf-8");
      const { metadata, body } = parseFrontmatter(content);
      _catalog.push(metadata);
      _bodies.set(metadata.name, body);
    } catch {
      // Skip directories without valid SKILL.md
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Return metadata for all available techniques.
 * Agents use this to decide which techniques to load at runtime.
 */
export function getTechniquesCatalog(): TechniqueMetadata[] {
  ensureLoaded();
  return _catalog!;
}

/**
 * Build a compact catalog string suitable for injection into system prompts.
 * Lists each technique with its name and description so the agent can
 * decide which ones to load via the `load_technique` tool.
 */
export function buildTechniquesCatalogPrompt(): string {
  const catalog = getTechniquesCatalog();
  if (catalog.length === 0) return "";

  const entries = catalog
    .map((t) => `- **${t.name}**: ${t.description}`)
    .join("\n");

  return `## Available Technique References

You have access to the following technique references. Use the \`load_technique\` tool to load any that are relevant to your current objectives. Review the descriptions and load only what you need — don't load everything.

${entries}`;
}

/**
 * Load a technique's body content by name (without frontmatter).
 */
export function loadTechnique(name: string): string {
  ensureLoaded();
  const body = _bodies!.get(name);
  if (!body) {
    throw new Error(
      `Technique "${name}" not found. Available: ${[..._bodies!.keys()].join(", ")}`,
    );
  }
  return body;
}
