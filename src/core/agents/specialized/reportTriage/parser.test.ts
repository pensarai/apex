import { mkdtemp, rm, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseReport } from "./parser";
import type { BountyReport } from "./types";

const CANONICAL_REPORT: BountyReport = {
  title: "Reflected XSS in search",
  reporterHandle: "researcher123",
  claimedSeverity: "HIGH",
  vulnerabilityClass: "Reflected XSS",
  affectedUrl: "https://staging.example.com/search?q=foo",
  affectedComponent: "search.q",
  attackerModel: "unauthenticated",
  description: "The q parameter is reflected without HTML encoding.",
  impact: "Session theft via cookie exfiltration.",
  pocSteps: [
    "GET /search?q=<script>alert(1)</script>",
    "Observe unencoded reflection",
  ],
  pocCurl: "curl 'https://staging.example.com/search?q=<script>alert(1)</script>'",
  references: [],
};

describe("parseReport — JSON fast path", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "triage-parser-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("validates a canonical JSON report without invoking the LLM", async () => {
    const filePath = join(dir, "report.json");
    await writeFile(filePath, JSON.stringify(CANONICAL_REPORT), "utf-8");

    const parsed = await parseReport({
      filePath,
      // Intentionally pass an invalid model — the fast path must not invoke
      // generateObjectResponse, so the model identifier should never be used.
      model: "this-model-does-not-exist" as never,
    });

    expect(parsed.title).toBe(CANONICAL_REPORT.title);
    expect(parsed.vulnerabilityClass).toBe("Reflected XSS");
    expect(parsed.pocSteps).toHaveLength(2);
  });

  it("recognises JSON content even when the extension is not .json", async () => {
    const filePath = join(dir, "report.txt");
    await writeFile(
      filePath,
      JSON.stringify(CANONICAL_REPORT, null, 2),
      "utf-8",
    );

    const parsed = await parseReport({
      filePath,
      model: "this-model-does-not-exist" as never,
    });

    expect(parsed.title).toBe(CANONICAL_REPORT.title);
  });
});
