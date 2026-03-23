import os from "os";
import path from "path";

/** Global skills directory: ~/.pensar/skills/ */
export const SKILLS_DIR = path.join(os.homedir(), ".pensar", "skills");

/** skills.sh CLI global install directory: ~/.agents/skills/ */
export const AGENTS_SKILLS_DIR = path.join(os.homedir(), ".agents", "skills");

/** Convert a display name to a filename-safe slug. */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
