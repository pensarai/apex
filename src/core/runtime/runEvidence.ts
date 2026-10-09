import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readdir, realpath, stat } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import type { SessionInfo } from "../session";

export interface EvidenceReference {
  /** POSIX path relative to the session root. */
  path: string;
  /** Lowercase hex SHA-256 of the file bytes at collection time. */
  sha256: string;
  /** Byte size of the file at collection time. */
  bytes: number;
}

export type EvidenceCheck =
  | { status: "match"; ref: EvidenceReference }
  | { status: "missing"; ref: EvidenceReference }
  | {
      status: "modified";
      ref: EvidenceReference;
      sha256: string;
      bytes: number;
    }
  | { status: "error"; ref: EvidenceReference; reason: string };

function isEnoent(error: unknown): boolean {
  return (error as { code?: string })?.code === "ENOENT";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function escapesRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  // "..hidden" stays inside the root; only real parent traversal escapes.
  return rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel);
}

function toPosix(p: string): string {
  return sep === "/" ? p : p.split(sep).join("/");
}

/** Stream the file so large tool-output spills never load fully into memory. */
async function digestOf(absolute: string): Promise<{
  sha256: string;
  bytes: number;
}> {
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(absolute)) {
    hash.update(chunk);
    bytes += chunk.length;
  }
  return { sha256: hash.digest("hex"), bytes };
}

function evidenceDirectories(session: SessionInfo): string[] {
  return [
    session.findingsPath,
    join(session.rootPath, "informational"),
    session.pocsPath,
    join(session.rootPath, "tasks"),
    join(session.rootPath, "tool-results"),
  ];
}

function evidenceFiles(session: SessionInfo): string[] {
  return [join(session.rootPath, "plan.md")];
}

async function collectFile(
  fileAbs: string,
  root: string,
  realRoot: string,
  refs: EvidenceReference[],
  optional: boolean,
): Promise<void> {
  let real: string;
  try {
    real = await realpath(fileAbs);
  } catch (error) {
    // Only known-top-level files (plan.md) may legitimately be absent; an
    // entry that readdir already saw must not vanish silently.
    if (optional && isEnoent(error)) return;
    throw error;
  }
  if (escapesRoot(realRoot, real)) {
    throw new Error(
      `evidence escapes session root: ${toPosix(relative(root, fileAbs))}`,
    );
  }
  const info = await stat(real);
  if (!info.isFile()) {
    throw new Error(
      `evidence is not a regular file: ${toPosix(relative(root, fileAbs))}`,
    );
  }
  const { sha256, bytes } = await digestOf(real);
  refs.push({ path: toPosix(relative(root, fileAbs)), sha256, bytes });
}

async function collectDirectory(
  dirAbs: string,
  root: string,
  realRoot: string,
  refs: EvidenceReference[],
  visitedDirs: Set<string>,
  optional: boolean,
): Promise<void> {
  let dirReal: string;
  try {
    dirReal = await realpath(dirAbs);
  } catch (error) {
    // Only a top-level known location may start absent; a directory the
    // parent readdir already observed must not vanish silently.
    if (optional && isEnoent(error)) return;
    throw error;
  }
  if (escapesRoot(realRoot, dirReal)) {
    throw new Error(
      `evidence directory escapes session root: ${toPosix(relative(root, dirAbs))}`,
    );
  }
  // Symlinked directories can loop; real paths make revisits idempotent.
  if (visitedDirs.has(dirReal)) return;
  visitedDirs.add(dirReal);

  const entries = await readdir(dirAbs, { withFileTypes: true });
  for (const entry of entries) {
    const childAbs = join(dirAbs, entry.name);
    if (entry.isDirectory()) {
      await collectDirectory(
        childAbs,
        root,
        realRoot,
        refs,
        visitedDirs,
        false,
      );
    } else if (entry.isFile()) {
      await collectFile(childAbs, root, realRoot, refs, false);
    } else {
      const childReal = await realpath(childAbs);
      if (escapesRoot(realRoot, childReal)) {
        throw new Error(
          `evidence escapes session root: ${toPosix(relative(root, childAbs))}`,
        );
      }
      const info = await stat(childReal);
      if (info.isFile()) {
        await collectFile(childAbs, root, realRoot, refs, false);
      } else if (info.isDirectory()) {
        await collectDirectory(
          childAbs,
          root,
          realRoot,
          refs,
          visitedDirs,
          false,
        );
      } else {
        throw new Error(
          `evidence is not a regular file: ${toPosix(relative(root, childAbs))}`,
        );
      }
    }
  }
}

/**
 * Inventory the session's evidence artifacts as digest references; the
 * session's domain files stay authoritative. Walks exactly the known
 * locations and throws on unreadable or root-escaping entries.
 */
export async function collectSessionEvidence(
  session: SessionInfo,
): Promise<EvidenceReference[]> {
  const root = resolve(session.rootPath);
  const realRoot = await realpath(root);
  const refs: EvidenceReference[] = [];
  const visitedDirs = new Set<string>([realRoot]);

  for (const directory of evidenceDirectories(session)) {
    await collectDirectory(
      resolve(directory),
      root,
      realRoot,
      refs,
      visitedDirs,
      true,
    );
  }
  for (const file of evidenceFiles(session)) {
    await collectFile(resolve(file), root, realRoot, refs, true);
  }

  refs.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return refs;
}

async function inspectReference(
  ref: EvidenceReference,
  root: string,
  realRoot: string,
): Promise<EvidenceCheck> {
  const abs = resolve(root, ref.path);
  if (escapesRoot(root, abs)) {
    return { status: "error", ref, reason: "reference escapes session root" };
  }
  let real: string;
  try {
    real = await realpath(abs);
  } catch (error) {
    if (isEnoent(error)) return { status: "missing", ref };
    return { status: "error", ref, reason: errorMessage(error) };
  }
  if (escapesRoot(realRoot, real)) {
    return { status: "error", ref, reason: "reference escapes session root" };
  }
  try {
    const info = await stat(real);
    if (!info.isFile()) {
      return { status: "error", ref, reason: "not a regular file" };
    }
    const digest = await digestOf(real);
    if (digest.sha256 === ref.sha256 && digest.bytes === ref.bytes) {
      return { status: "match", ref };
    }
    return {
      status: "modified",
      ref,
      sha256: digest.sha256,
      bytes: digest.bytes,
    };
  } catch (error) {
    return { status: "error", ref, reason: errorMessage(error) };
  }
}

/**
 * Verify references one at a time (bounded open files) against the session's
 * current files. Missing, modified, and error are distinct; nothing is
 * restored.
 */
export async function inspectSessionEvidence(
  session: Pick<SessionInfo, "rootPath">,
  refs: EvidenceReference[],
): Promise<EvidenceCheck[]> {
  const root = resolve(session.rootPath);
  const realRoot = await realpath(root).catch((error: unknown) => {
    if (isEnoent(error)) return null;
    throw error;
  });
  if (realRoot === null) {
    return refs.map((ref) => ({ status: "missing" as const, ref }));
  }
  const checks: EvidenceCheck[] = [];
  for (const ref of refs) {
    checks.push(await inspectReference(ref, root, realRoot));
  }
  return checks;
}
