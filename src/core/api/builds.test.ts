import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const apiRequest = vi.hoisted(() => vi.fn());
const readFile = vi.hoisted(() => vi.fn());

vi.mock("./apiClient", () => ({ apiRequest }));
vi.mock("node:fs/promises", () => ({ readFile }));

import { uploadDesktopBuild } from "./builds";

const BYTES = Buffer.from("fake-appimage-bytes");
const EXPECTED_SHA = createHash("sha256").update(BYTES).digest("hex");

describe("uploadDesktopBuild", () => {
  beforeEach(() => {
    apiRequest.mockReset();
    readFile.mockReset();
    readFile.mockResolvedValue(BYTES);
    apiRequest
      .mockResolvedValueOnce({
        releaseId: "rel-1",
        artifactId: "art-1",
        s3Key: "workspaces/ws/app/rel-1/artifacts/art-1/app.AppImage",
        uploadUrl: "https://s3.example/put?sig=1",
        expiresInSeconds: 600,
      })
      .mockResolvedValueOnce({
        artifact: {
          id: "art-1",
          release: "rel-1",
          filename: "app.AppImage",
          platform: "linux",
          architecture: "x64",
          format: "appimage",
          size: BYTES.byteLength,
          sha256: EXPECTED_SHA,
          uploadStatus: "uploaded",
          scanStatus: "pending",
        },
      });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue({ ok: true, status: 200, text: async () => "" }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("presigns with a detected filename + size, PUTs bytes, then finalizes with the sha256", async () => {
    const artifact = await uploadDesktopBuild({
      filePath: "/tmp/dist/app.AppImage",
      application: "APP-3",
      version: "1.4.2",
      platform: "linux",
    });

    // presign
    expect(apiRequest).toHaveBeenNthCalledWith(
      1,
      "POST",
      "/api/cli/artifacts/presign",
      expect.objectContaining({
        application: "APP-3",
        version: "1.4.2",
        platform: "linux",
        fileName: "app.AppImage",
        size: BYTES.byteLength,
        contentType: "application/octet-stream",
      }),
    );

    // direct S3 PUT with the same content-type presign signed
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    expect(fetchMock).toHaveBeenCalledWith(
      "https://s3.example/put?sig=1",
      expect.objectContaining({
        method: "PUT",
        headers: { "Content-Type": "application/octet-stream" },
      }),
    );

    // finalize with the locally-computed hash
    expect(apiRequest).toHaveBeenNthCalledWith(
      2,
      "POST",
      "/api/cli/artifacts/finalize",
      { artifactId: "art-1", sha256: EXPECTED_SHA },
    );

    expect(artifact.id).toBe("art-1");
    expect(artifact.uploadStatus).toBe("uploaded");
  });

  it("forwards provenance + ci sourceKind in the presign call", async () => {
    await uploadDesktopBuild({
      filePath: "/tmp/dist/App.exe",
      application: "APP-3",
      version: "2.0.0",
      platform: "windows",
      sourceKind: "ci",
      source: { commitSha: "deadbeef", repositoryId: "repo-uuid" },
    });
    expect(apiRequest).toHaveBeenNthCalledWith(
      1,
      "POST",
      "/api/cli/artifacts/presign",
      expect.objectContaining({
        sourceKind: "ci",
        source: { commitSha: "deadbeef", repositoryId: "repo-uuid" },
      }),
    );
  });

  it("throws when the S3 PUT fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        text: async () => "denied",
      }),
    );
    await expect(
      uploadDesktopBuild({
        filePath: "/tmp/dist/app.AppImage",
        application: "APP-3",
        version: "1.4.2",
        platform: "linux",
      }),
    ).rejects.toThrow(/upload to storage failed \(403\)/);
    // finalize must not be called after a failed PUT
    expect(apiRequest).toHaveBeenCalledTimes(1);
  });

  it("rejects an empty file before calling the API", async () => {
    readFile.mockResolvedValue(Buffer.alloc(0));
    await expect(
      uploadDesktopBuild({
        filePath: "/tmp/empty.AppImage",
        application: "APP-3",
        version: "1.4.2",
        platform: "linux",
      }),
    ).rejects.toThrow(/File is empty/);
    expect(apiRequest).not.toHaveBeenCalled();
  });
});
