import { readdir, readFile, stat } from "fs/promises";
import { join } from "path";
import type { ProgramContext } from "./types";

const BUG_BOUNTY_DIR = ".apex/bug-bounty";
const THREAT_MODELS_DIR = ".apex/threat-models";

const SCOPE_FILE = "scope.md";
const ENGAGEMENT_FILE = "engagement.md";
const BUSINESS_CONTEXT_FILE = "business-context.md";

const MAX_BYTES_PER_FILE = 100_000;

async function readOptional(path: string): Promise<string | null> {
  try {
    const content = await readFile(path, "utf-8");
    if (content.length > MAX_BYTES_PER_FILE) {
      return `${content.slice(0, MAX_BYTES_PER_FILE)}\n\n[...truncated — file exceeded ${MAX_BYTES_PER_FILE} bytes]`;
    }
    return content;
  } catch {
    return null;
  }
}

/**
 * Find the most recently modified `.md` file inside `dir`, returning its
 * absolute path. Returns `null` if the directory is missing or empty.
 */
async function findLatestMarkdown(dir: string): Promise<string | null> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return null;
  }

  const mdEntries = entries.filter((e) => e.toLowerCase().endsWith(".md"));
  if (mdEntries.length === 0) return null;

  const withMtime = await Promise.all(
    mdEntries.map(async (name) => {
      const full = join(dir, name);
      try {
        const s = await stat(full);
        return { path: full, mtime: s.mtimeMs };
      } catch {
        return null;
      }
    }),
  );

  const valid = withMtime.filter(
    (e): e is { path: string; mtime: number } => e !== null,
  );
  if (valid.length === 0) return null;

  valid.sort((a, b) => b.mtime - a.mtime);
  return valid[0]!.path;
}

/**
 * Load convention-based program context from the repo at `cwd`.
 *
 * Looks for:
 *  - `<cwd>/.apex/bug-bounty/scope.md`
 *  - `<cwd>/.apex/bug-bounty/engagement.md`
 *  - `<cwd>/.apex/bug-bounty/business-context.md`
 *  - The most recently modified `*.md` in `<cwd>/.apex/threat-models/`
 *
 * Missing files are non-fatal — they're returned as `null` and the caller
 * is expected to degrade gracefully (e.g. skip threat-model alignment when
 * no threat model is present).
 */
export async function loadProgramContext(cwd: string): Promise<ProgramContext> {
  const bountyDir = join(cwd, BUG_BOUNTY_DIR);
  const threatDir = join(cwd, THREAT_MODELS_DIR);

  const [scope, engagement, businessContext, threatModelPath] =
    await Promise.all([
      readOptional(join(bountyDir, SCOPE_FILE)),
      readOptional(join(bountyDir, ENGAGEMENT_FILE)),
      readOptional(join(bountyDir, BUSINESS_CONTEXT_FILE)),
      findLatestMarkdown(threatDir),
    ]);

  const threatModel = threatModelPath
    ? await readOptional(threatModelPath)
    : null;

  return {
    scope,
    engagement,
    businessContext,
    threatModel,
    threatModelPath,
  };
}
