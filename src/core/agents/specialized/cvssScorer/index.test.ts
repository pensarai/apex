import type { LanguageModelMiddleware } from "ai";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateObjectResponse } from "../../../ai";
import { type CVSSScorerInput, scoreFindingWithCVSS } from "./index";

vi.mock("../../../ai", () => ({
  generateObjectResponse: vi.fn(),
}));

const mockedGenerate = vi.mocked(generateObjectResponse);

const input: CVSSScorerInput = {
  finding: {
    title: "SQL Injection in /api/products",
    description: "The search parameter is concatenated into a SQL query.",
    impact: "Full database read.",
    evidence: "' OR 1=1 -- returned every row.",
    endpoint: "https://target.com/api/products",
    vulnerabilityClass: "sql-injection",
  },
  agentMessages: [],
};

const assessment = {
  metrics: {
    AV: "N",
    AC: "L",
    AT: "N",
    PR: "N",
    UI: "N",
    VC: "H",
    VI: "H",
    VA: "H",
    SC: "N",
    SI: "N",
    SA: "N",
    E: "A",
  },
  reasoning: "Unauthenticated, network-reachable injection with full impact.",
  cwes: [{ id: "CWE-89", reasoning: "Unsanitized input reaches a SQL query." }],
};

describe("scoreFindingWithCVSS hooks", () => {
  beforeEach(() => {
    mockedGenerate.mockReset();
    mockedGenerate.mockResolvedValue(assessment);
  });

  it("forwards languageModelMiddleware and usageRecorder to the structured call", async () => {
    const languageModelMiddleware: LanguageModelMiddleware = {
      specificationVersion: "v3",
    };
    const usageRecorder = vi.fn();
    const abortSignal = new AbortController().signal;

    await scoreFindingWithCVSS(
      input,
      "test-model",
      undefined,
      abortSignal,
      "ses_cvss",
      { languageModelMiddleware, usageRecorder },
    );

    expect(mockedGenerate).toHaveBeenCalledOnce();
    expect(mockedGenerate).toHaveBeenCalledWith(
      expect.objectContaining({
        model: "test-model",
        abortSignal,
        sessionId: "ses_cvss",
        operation: "apex.finding.cvss",
        languageModelMiddleware,
        usageRecorder,
      }),
    );
  });

  it("passes no hooks when the caller supplies none", async () => {
    const result = await scoreFindingWithCVSS(input, "test-model");

    const call = mockedGenerate.mock.calls[0]?.[0];
    expect(call?.languageModelMiddleware).toBeUndefined();
    expect(call?.usageRecorder).toBeUndefined();
    expect(result.vectorString).toMatch(/^CVSS:4\.0\//);
    expect(result.cwes.map((c) => c.id)).toEqual(["CWE-89"]);
  });
});
