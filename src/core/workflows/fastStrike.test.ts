import { describe, expect, it } from "vitest";
import {
  FAST_STRIKE_SYSTEM_PROMPT,
  normalizeFastStrikeOutcome,
  rejectUnverifiedFastStrikeResponse,
  requestsExactFlag,
  resolveFastStrikeLaneTimeoutMs,
  runCompetitiveLanes,
} from "./fastStrike";

describe("Fast Strike objective contract", () => {
  it("keeps the prompt impact-oriented and production-safe", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "one authorized impact objective",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("editable script");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("trace-linked evidence");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("destructive actions");
    expect(FAST_STRIKE_SYSTEM_PROMPT).not.toContain("Argus");
  });

  it("defaults a single lane to no harness deadline", () => {
    expect(resolveFastStrikeLaneTimeoutMs(1)).toBeUndefined();
    expect(resolveFastStrikeLaneTimeoutMs(2)).toBe(30 * 60 * 1000);
    expect(resolveFastStrikeLaneTimeoutMs(1, 90_000)).toBe(90_000);
  });

  it("recognizes objectives that require an exact flag", () => {
    expect(requestsExactFlag("Return the exact FLAG{...} value")).toBe(true);
    expect(requestsExactFlag("Demonstrate account takeover")).toBe(false);
  });

  it("downgrades unsupported impact claims", () => {
    expect(
      normalizeFastStrikeOutcome(
        {
          status: "impact-proven",
          summary: "Claimed compromise",
          evidence: [
            {
              description: "response",
              toolCallId: "call-1",
              toolName: "http_request",
            },
          ],
        },
        { validateImpactEvidence: () => "not observed" },
      ).status,
    ).toBe("exhausted");
  });

  it("asks for correction when impact evidence is missing", () => {
    const rejection = rejectUnverifiedFastStrikeResponse(
      { status: "impact-proven", summary: "done" },
      {
        exactFlagRequired: false,
        rejectionCount: 0,
        validateImpactEvidence: () => "missing evidence",
      },
    );
    expect(rejection?.message).toContain("missing evidence");
  });
});

describe("competitive Fast Strike lanes", () => {
  it("returns the first impact-proven result and aborts siblings", async () => {
    let siblingAborted = false;
    const result = await runCompetitiveLanes<{
      status: "impact-proven" | "exhausted";
    }>(
      [
        async () => ({ status: "impact-proven" as const }),
        async (signal) =>
          await new Promise<{ status: "exhausted" }>((resolve) => {
            signal.addEventListener("abort", () => {
              siblingAborted = true;
              resolve({ status: "exhausted" });
            });
          }),
      ],
      (candidate) => candidate.status === "impact-proven",
    );
    expect(result.status).toBe("impact-proven");
    expect(siblingAborted).toBe(true);
  });
});
