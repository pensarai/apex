import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { documentEndpointV2 } from "./documentEndpointV2";
import {
  createToolsForNames,
  DEFAULT_V2_EXCLUDED_TOOL_NAMES,
  listToolRegistryNames,
} from "./index";
import type { ToolContext } from "./types";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
async function context(): Promise<ToolContext> {
  const rootPath = await mkdtemp(join(tmpdir(), "apex-endpoint-v2-"));
  roots.push(rootPath);
  return {
    mode: "default-v2",
    session: {
      id: "ses_endpoint",
      rootPath,
      targets: ["https://example.test"],
    },
  } as ToolContext;
}
const input = {
  appName: "../../application",
  routePath: "/api/items",
  endpointType: "api-endpoint" as const,
  description: "Returns HTTP 401 without a session cookie",
  evidence: ["scratchpad/request.txt:1"],
  toolCallDescription: "Save the observed endpoint",
};
const options = { context: {}, toolCallId: "record", messages: [] };

describe("v2 endpoint evidence", () => {
  it("writes only supplied observations without registry analysis or threat generation", async () => {
    const ctx = await context();
    const register = vi.fn(() => {
      throw new Error("Unexpected analysis path");
    });
    ctx.attackSurfaceRegistry = {
      register,
    } as unknown as ToolContext["attackSurfaceRegistry"];
    const execute = documentEndpointV2(ctx).execute;
    if (!execute) throw new Error("Missing execution");
    const result = await execute(input, options);
    if (!("filepath" in result)) throw new Error("Unexpected streaming result");
    expect(
      result.filepath.startsWith(
        join(ctx.session.rootPath, "observations", "endpoints") + "/",
      ),
    ).toBe(true);
    const saved = JSON.parse(await readFile(result.filepath, "utf8"));
    expect(saved).toMatchObject({
      description: input.description,
      evidence: input.evidence,
      schemaVersion: 2,
      sessionId: ctx.session.id,
    });
    for (const field of [
      "riskScore",
      "riskLevel",
      "pentestObjectives",
      "threatModel",
      "businessLogic",
      "toolCallDescription",
    ])
      expect(saved).not.toHaveProperty(field);
    expect(register).not.toHaveBeenCalled();
    await expect(
      execute(
        { ...input, routePath: "https://example.test/api/items" },
        options,
      ),
    ).rejects.toThrow("Use a route");
  });

  it("removes legacy workflows from registry construction and discovery in v2", async () => {
    const ctx = await context();
    const names = [...DEFAULT_V2_EXCLUDED_TOOL_NAMES, "document_endpoint_v2"];
    expect(Object.keys(createToolsForNames(ctx, names))).toEqual([
      "document_endpoint_v2",
    ]);
    expect(listToolRegistryNames(ctx)).toContain("document_endpoint_v2");
    for (const name of DEFAULT_V2_EXCLUDED_TOOL_NAMES)
      expect(listToolRegistryNames(ctx)).not.toContain(name);
    expect(listToolRegistryNames({ ...ctx, mode: "default" })).not.toContain(
      "document_endpoint_v2",
    );
  });
});
