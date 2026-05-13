import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import type { SessionInfo } from "../session";
import { resolveSessionWhiteboxArtifactPath } from "./paths";
import type { WhiteboxArtifactRef, WhiteboxArtifactType } from "./types";

const MAX_ARTIFACT_INLINE_CHARS = 40_000;

function safeName(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

export function getWhiteboxLogsDir(session: SessionInfo): string {
  return join(session.logsPath, "whitebox");
}

export function getWhiteboxScratchDir(session: SessionInfo): string {
  return join(session.scratchpadPath, "whitebox");
}

export async function ensureWhiteboxDirs(session: SessionInfo): Promise<void> {
  await Promise.all([
    mkdir(getWhiteboxLogsDir(session), { recursive: true }),
    mkdir(getWhiteboxScratchDir(session), { recursive: true }),
  ]);
}

export async function writeWhiteboxArtifact(input: {
  session: SessionInfo;
  area?: "logs" | "scratchpad";
  type: WhiteboxArtifactType;
  name: string;
  content: string;
  description: string;
  extension?: string;
}): Promise<WhiteboxArtifactRef> {
  await ensureWhiteboxDirs(input.session);
  const baseDir =
    input.area === "scratchpad"
      ? getWhiteboxScratchDir(input.session)
      : getWhiteboxLogsDir(input.session);
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `${timestamp}-${safeName(input.name)}${input.extension ?? ".txt"}`;
  const absolutePath = join(baseDir, filename);
  await writeFile(absolutePath, input.content, "utf-8");

  const relativeRoot =
    input.area === "scratchpad" ? "scratchpad/whitebox" : "logs/whitebox";
  return {
    path: `${relativeRoot}/${basename(absolutePath)}`,
    type: input.type,
    description: input.description,
  };
}

export async function readWhiteboxArtifact(input: {
  session: SessionInfo;
  path: string;
}): Promise<{
  content: string;
  truncated: boolean;
  absolutePath: string;
}> {
  const absolutePath = resolveSessionWhiteboxArtifactPath({
    sessionRootPath: input.session.rootPath,
    artifactRelativePath: input.path,
  });
  const raw = await readFile(absolutePath, "utf-8");
  if (raw.length <= MAX_ARTIFACT_INLINE_CHARS) {
    return { content: raw, truncated: false, absolutePath };
  }
  return {
    content: `${raw.slice(0, MAX_ARTIFACT_INLINE_CHARS)}\n\n(truncated - read the artifact in smaller chunks if needed)`,
    truncated: true,
    absolutePath,
  };
}
