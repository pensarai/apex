import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { documentEndpoint } from "./documentEndpoint";
import { generateThreatModelForEndpoint } from "./threatModelGenerator";

vi.mock("./threatModelGenerator", () => ({
  generateThreatModelForEndpoint: vi.fn(),
}));
const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

describe("document_endpoint scope recommendation", () => {
  it.each([
    true,
    false,
  ])("keeps the endpoint documented when excludeByDefault=%s", async (excludeByDefault) => {
    const rootPath = mkdtempSync(join(tmpdir(), "endpoint-scope-test-"));
    dirs.push(rootPath);
    const scopeRecommendation = {
      category: "health_probe" as const,
      excludeByDefault,
      reason: "Observed a constant OK response.",
    };
    vi.mocked(generateThreatModelForEndpoint).mockResolvedValue({
      scopeRecommendation,
      businessLogic: "Probe",
      threatModel: "No sensitive data observed",
      pentestObjectives: [],
      riskScore: {
        score: 0,
        explanation: "Probe",
        breakdown: {
          exposure: 0,
          dataSensitivity: 0,
          functionCriticality: 0,
          securityIndicators: 0,
        },
      },
    });
    const tool = documentEndpoint({
      session: { id: "session-1", rootPath, targets: ["https://example.com"] },
    } as Parameters<typeof documentEndpoint>[0]);
    if (!tool.execute) throw new Error("document_endpoint must be executable");
    const result = await tool.execute(
      {
        appName: "API",
        routePath: "/health",
        endpointType: "api-endpoint",
        description: "Health probe",
        notes: "Observed a constant OK response.",
        method: "GET",
        riskLevel: "LOW",
        toolCallDescription: "Document health probe",
      },
      { toolCallId: "call-1", messages: [] },
    );
    expect(result).toMatchObject({ success: true, scopeRecommendation });
    expect(generateThreatModelForEndpoint).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ notes: "Observed a constant OK response." }),
    );
    const record = JSON.parse(
      readFileSync((result as { filepath: string }).filepath, "utf8"),
    );
    expect(record.scopeRecommendation).toEqual(scopeRecommendation);
    expect(record.routePath).toBe("/health");
  });
});
