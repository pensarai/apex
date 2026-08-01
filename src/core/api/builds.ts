/**
 * Desktop-app build artifact upload against the Pensar Console API.
 *
 * Three steps, mirroring the browser flow:
 *   1. presign  — POST /api/cli/artifacts/presign  → { artifactId, uploadUrl }
 *   2. PUT bytes directly to S3 (not through the API — avoids gateway payload
 *      limits for multi-hundred-MB installers)
 *   3. finalize — POST /api/cli/artifacts/finalize  → { artifact }
 *
 * `apiRequest` is JSON-only, so the raw byte PUT uses `fetch` directly with the
 * exact Content-Type sent to presign (SigV4 signs that header).
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { apiRequest } from "./apiClient";

export type ArtifactPlatform = "linux" | "windows" | "macos";
export type ReleaseChannel = "stable" | "beta" | "nightly" | "dev";

export interface UploadBuildInput {
  filePath: string;
  application: string; // application id or applicationLabel
  version: string;
  platform: ArtifactPlatform;
  architecture?: string;
  channel?: ReleaseChannel;
  format?: string;
  contentType?: string;
  sourceKind?: "upload" | "ci" | "release-url";
  source?: {
    repositoryId?: string;
    commitSha?: string;
    ref?: string;
    repositoryPath?: string;
    buildUrl?: string;
    workflowRunId?: string;
  };
}

export interface UploadedArtifact {
  id: string;
  release: string;
  filename: string;
  platform: string;
  architecture: string;
  format: string;
  size: number | null;
  sha256: string | null;
  uploadStatus: string;
  scanStatus: string;
}

interface PresignResponse {
  releaseId: string;
  artifactId: string;
  s3Key: string;
  uploadUrl: string;
  expiresInSeconds: number;
}

// Minimal extension → MIME guess. Falls back to octet-stream; the server treats
// content-type as advisory (format drives behavior).
function guessContentType(fileName: string): string {
  const lower = fileName.toLowerCase();
  if (lower.endsWith(".zip")) return "application/zip";
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz"))
    return "application/gzip";
  if (lower.endsWith(".deb")) return "application/vnd.debian.binary-package";
  if (lower.endsWith(".rpm")) return "application/x-rpm";
  if (lower.endsWith(".dmg")) return "application/x-apple-diskimage";
  if (lower.endsWith(".exe") || lower.endsWith(".msi"))
    return "application/octet-stream";
  return "application/octet-stream";
}

export async function uploadDesktopBuild(
  input: UploadBuildInput,
): Promise<UploadedArtifact> {
  const fileName = path.basename(input.filePath);
  const bytes = await readFile(input.filePath);
  const size = bytes.byteLength;
  if (size === 0) {
    throw new Error(`File is empty: ${input.filePath}`);
  }
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const contentType = input.contentType ?? guessContentType(fileName);

  const presign = await apiRequest<PresignResponse>(
    "POST",
    "/api/cli/artifacts/presign",
    {
      application: input.application,
      version: input.version,
      platform: input.platform,
      architecture: input.architecture,
      channel: input.channel,
      format: input.format,
      contentType,
      fileName,
      size,
      sourceKind: input.sourceKind,
      source: input.source,
    },
  );

  // Direct S3 PUT. Content-Type must match what presign signed.
  const putResponse = await fetch(presign.uploadUrl, {
    method: "PUT",
    body: bytes,
    headers: { "Content-Type": contentType },
  });
  if (!putResponse.ok) {
    const text = await putResponse.text().catch(() => "");
    throw new Error(
      `Artifact upload to storage failed (${putResponse.status}): ${text}`,
    );
  }

  const { artifact } = await apiRequest<{ artifact: UploadedArtifact }>(
    "POST",
    "/api/cli/artifacts/finalize",
    { artifactId: presign.artifactId, sha256 },
  );

  return artifact;
}
