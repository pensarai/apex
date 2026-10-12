import { mkdir, open, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { StringDecoder } from "node:string_decoder";
import type { SessionInfo } from "../session";
import { resolveSessionWhiteboxArtifactPath } from "./paths";
import type { WhiteboxArtifactRef, WhiteboxArtifactType } from "./types";

const MAX_ARTIFACT_INLINE_CHARS = 40_000;
const PREVIEW_READ_CHUNK_BYTES = 16_384;

function safeName(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/\.{2,}/g, ".")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

export function getWhiteboxLogsDir(session: SessionInfo): string {
  return join(session.logsPath, "whitebox");
}

function getWhiteboxScratchDir(session: SessionInfo): string {
  return join(session.scratchpadPath, "whitebox");
}

async function ensureWhiteboxDirs(session: SessionInfo): Promise<void> {
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

/**
 * Read at most `maxChars` UTF-16 code units of a UTF-8 file, touching only the
 * prefix bytes. Indistinguishable from `readFile(path, "utf8")` followed by
 * `.slice(0, maxChars)` — malformed or truncated byte sequences decode to the
 * same replacement characters, and a slice landing inside a surrogate pair
 * keeps the lone half exactly like String#slice.
 */
export async function readTextPrefix(
  path: string,
  maxChars: number,
): Promise<{ content: string; truncated: boolean; bytesRead: number }> {
  if (!Number.isInteger(maxChars) || maxChars < 0) {
    throw new RangeError(
      `maxChars must be a non-negative integer: ${maxChars}`,
    );
  }
  const file = await open(path, "r");
  const decoder = new StringDecoder("utf8");
  const chunk = Buffer.allocUnsafe(PREVIEW_READ_CHUNK_BYTES);
  let decoded = "";
  let bytesRead = 0;
  try {
    while (decoded.length <= maxChars) {
      const { bytesRead: read } = await file.read(chunk, 0, chunk.length, null);
      if (read === 0) {
        decoded += decoder.end();
        break;
      }
      bytesRead += read;
      decoded += decoder.write(chunk.subarray(0, read));
    }
    return {
      content: decoded.slice(0, maxChars),
      truncated: decoded.length > maxChars,
      bytesRead,
    };
  } finally {
    await file.close();
  }
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
  const { content, truncated } = await readTextPrefix(
    absolutePath,
    MAX_ARTIFACT_INLINE_CHARS,
  );
  if (!truncated) {
    return { content, truncated: false, absolutePath };
  }
  return {
    content: `${content}\n\n(truncated - read the artifact in smaller chunks if needed)`,
    truncated: true,
    absolutePath,
  };
}
