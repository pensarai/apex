import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { documentApp } from "./documentApp";

function makeContext(rootPath: string, target: string) {
  return {
    session: {
      id: "test-session",
      rootPath,
      targets: [target],
    },
    agentCwd: rootPath,
  } as Parameters<typeof documentApp>[0];
}

function makeInput(appType: "web_application" | "api" | "cloud_resource") {
  return {
    appName: "Primary App",
    appType,
    description: "Application discovered during reconnaissance",
    toolCallDescription: "Document the discovered application",
  };
}

describe("documentApp domain handling", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-app-"));
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  it("defaults a primary web app domain to the session target origin", async () => {
    const tool = documentApp(
      makeContext(rootPath, "https://example.com/recon/start?source=test"),
    );
    const result = (await tool.execute?.(makeInput("web_application"), {
      toolCallId: "tool-1",
      messages: [],
    })) as { success: boolean; domain?: string; filepath: string };

    expect(result.success).toBe(true);
    expect(result.domain).toBe("https://example.com");
    expect(JSON.parse(readFileSync(result.filepath, "utf8")).domain).toBe(
      "https://example.com",
    );
  });

  it("leaves the domain unset when the session target is not an HTTP URL", async () => {
    const tool = documentApp(makeContext(rootPath, "/workspace/source"));
    const result = (await tool.execute?.(makeInput("api"), {
      toolCallId: "tool-2",
      messages: [],
    })) as { success: boolean; domain?: string; filepath: string };

    expect(result.success).toBe(true);
    expect(result.domain).toBeUndefined();
    expect(
      JSON.parse(readFileSync(result.filepath, "utf8")),
    ).not.toHaveProperty("domain");
  });

  it("does not apply the session target to a cloud resource", async () => {
    const tool = documentApp(makeContext(rootPath, "https://example.com"));
    const result = (await tool.execute?.(makeInput("cloud_resource"), {
      toolCallId: "tool-3",
      messages: [],
    })) as { success: boolean; domain?: string; filepath: string };

    expect(result.success).toBe(true);
    expect(result.domain).toBeUndefined();
    expect(
      JSON.parse(readFileSync(result.filepath, "utf8")),
    ).not.toHaveProperty("domain");
  });
});
