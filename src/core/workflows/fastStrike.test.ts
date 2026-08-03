import { describe, expect, it, vi } from "vitest";
import { FAST_STRIKE_EXCLUDED_TOOL_NAMES } from "../agents/offSecAgent/tools";
import {
  buildFastStrikeRecoveryDossier,
  FAST_STRIKE_SYSTEM_PROMPT,
  FastStrikeResult,
  normalizeFastStrikeOutcome,
  rejectUnverifiedFastStrikeResponse,
  requestsExactFlag,
  resolveFastStrikeLaneTimeoutMs,
  runCompetitiveLanes,
} from "./fastStrike";

type Outcome = {
  status: "impact-proven" | "exhausted" | "blocked";
  lane: number;
};

describe("runCompetitiveLanes", () => {
  it("reserves recovery time for competitive lanes while leaving one lane unlimited", () => {
    expect(resolveFastStrikeLaneTimeoutMs(1)).toBeUndefined();
    expect(resolveFastStrikeLaneTimeoutMs(2)).toBe(30 * 60 * 1000);
    expect(resolveFastStrikeLaneTimeoutMs(3)).toBe(30 * 60 * 1000);
    expect(resolveFastStrikeLaneTimeoutMs(3, 900_000)).toBe(900_000);
  });

  it("returns the first impact-proven result and cancels remaining lanes", async () => {
    let resolveWinner!: (value: Outcome) => void;
    const loserAborted = vi.fn();
    const resultPromise = runCompetitiveLanes<Outcome>(
      [
        (signal) =>
          new Promise<Outcome>((_resolve, reject) => {
            signal.addEventListener("abort", () => {
              loserAborted();
              reject(new DOMException("Aborted", "AbortError"));
            });
          }),
        () =>
          new Promise<Outcome>((resolve) => {
            resolveWinner = resolve;
          }),
      ],
      (outcome) => outcome.status === "impact-proven",
    );

    resolveWinner({ status: "impact-proven", lane: 2 });
    await expect(resultPromise).resolves.toEqual({
      status: "impact-proven",
      lane: 2,
    });
    expect(loserAborted).toHaveBeenCalledOnce();
  });

  it("returns an honest non-impact result after every lane settles", async () => {
    const result = await runCompetitiveLanes<Outcome>(
      [
        async () => ({ status: "exhausted", lane: 1 }),
        async () => ({ status: "blocked", lane: 2 }),
      ],
      (outcome) => outcome.status === "impact-proven",
    );

    expect(result.status).not.toBe("impact-proven");
    expect([1, 2]).toContain(result.lane);
  });
});

describe("fast-strike objective result", () => {
  it("uses an objective-scoped status instead of a global solved flag", () => {
    expect(
      FastStrikeResult.safeParse({
        status: "impact-proven",
        summary: "Proved account takeover",
        evidence: [
          {
            description: "Protected profile returned after session takeover",
            reference: "GET /account -> 200",
          },
        ],
      }).success,
    ).toBe(true);
    expect(
      FastStrikeResult.safeParse({
        solved: true,
        summary: "Legacy global completion claim",
      }).success,
    ).toBe(false);
  });

  it("turns a missing response into a blocked lane handoff", () => {
    expect(normalizeFastStrikeOutcome(undefined)).toEqual({
      status: "blocked",
      summary:
        "Lane ended without a valid accepted response; sibling lanes may continue.",
    });
  });

  it("preserves a valid impact-proven response", () => {
    expect(
      normalizeFastStrikeOutcome({
        status: "impact-proven",
        summary: "Recovered protected customer records",
      }),
    ).toEqual({
      status: "impact-proven",
      summary: "Recovered protected customer records",
    });
  });

  it("downgrades a flag objective without the literal proof", () => {
    expect(
      normalizeFastStrikeOutcome(
        {
          status: "impact-proven",
          summary: "Reached the protected secret",
        },
        { exactFlagRequired: true },
      ),
    ).toEqual({
      status: "exhausted",
      summary:
        "Lane claimed impact without the required literal FLAG{...} proof. Reached the protected secret",
      evidence: undefined,
    });
  });

  it("accepts exact proof in a concrete evidence reference", () => {
    expect(
      normalizeFastStrikeOutcome(
        {
          status: "impact-proven",
          summary: "Exfiltration succeeded",
          evidence: [
            {
              description: "Protected response contained FLAG{literal-proof}",
              reference: "tool call request-42",
            },
          ],
        },
        { exactFlagRequired: true },
      ).status,
    ).toBe("impact-proven");
  });
});

describe("buildFastStrikeRecoveryDossier", () => {
  it("preserves settled lane handoffs in lane order", () => {
    expect(
      buildFastStrikeRecoveryDossier([
        { status: "exhausted", summary: "confirmed SSRF" },
        undefined,
        { status: "blocked", summary: "callback ingress unavailable" },
      ]),
    ).toBe(
      "Lane 1 (status=exhausted):\nconfirmed SSRF\n\n---\n\nLane 3 (status=blocked):\ncallback ingress unavailable",
    );
  });

  it("bounds each handoff before injecting recovery context", () => {
    const dossier = buildFastStrikeRecoveryDossier([
      { status: "exhausted", summary: "x".repeat(7000) },
    ]);
    expect(dossier.length).toBeLessThan(6100);
  });
});

describe("fast-strike capability and scope guidance", () => {
  it("treats a causal flag capture as impact without a fixed layer count", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "valid proof of data exfiltration",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "do not need to reproduce an expected route",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "Verify causality between the exploit primitive and the material impact",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).not.toContain("verifiedLayers");
    expect(FAST_STRIKE_SYSTEM_PROMPT).not.toContain(
      "at least 6 distinct target-side",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).not.toContain(
      "alternate HTTP protocol version",
    );
  });

  it("keeps service discovery bounded and target-local", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("ports 1-10000");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("at most 100 probes/second");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("only against that host");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "at most 12 internal host:port",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "do not scan external DNS or the public Internet",
    );
  });

  it("bounds custom authentication canonicalization recovery", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "matrix of at most 24 canonicalizations",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("never guess keys or secrets");
  });
});

describe("fast-strike tool envelope", () => {
  it("omits orchestration while preserving production contract tools", () => {
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).toContain("spawn_pentest_agent");
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).toContain("document_app");
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).not.toContain(
      "document_vulnerability",
    );
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).not.toContain("checkpoint_state");
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).not.toContain("browser_screenshot");
  });
});

describe("fast-strike response verification", () => {
  it("detects exact-flag objectives without treating placeholders as proof", () => {
    expect(requestsExactFlag("Find the flag (format: FLAG{...})")).toBe(true);
    expect(requestsExactFlag("Return the exact flag value")).toBe(true);
    expect(requestsExactFlag("Confirm account takeover")).toBe(false);

    expect(
      rejectUnverifiedFastStrikeResponse(
        { status: "impact-proven", summary: "Recovered FLAG{...}" },
        { exactFlagRequired: true, rejectionCount: 0 },
      )?.message,
    ).toContain("does not contain the exact recovered");
  });

  it("accepts impact when literal requested proof is present", () => {
    expect(
      rejectUnverifiedFastStrikeResponse(
        { status: "impact-proven", summary: "Recovered FLAG{literal-value}" },
        { exactFlagRequired: true, rejectionCount: 0 },
      ),
    ).toBeUndefined();
  });

  it("accepts honest exhausted and blocked outcomes", () => {
    for (const status of ["exhausted", "blocked"] as const) {
      expect(
        rejectUnverifiedFastStrikeResponse(
          { status, summary: "No material impact proved" },
          { exactFlagRequired: true, rejectionCount: 0 },
        ),
      ).toBeUndefined();
    }
  });

  it("keeps correction of an invalid impact claim bounded", () => {
    expect(
      rejectUnverifiedFastStrikeResponse(
        { status: "impact-proven", summary: "Missing literal proof" },
        { exactFlagRequired: true, rejectionCount: 3 },
      )?.message,
    ).toContain("marked impact proven");
    expect(
      rejectUnverifiedFastStrikeResponse(
        { status: "impact-proven", summary: "Missing literal proof" },
        { exactFlagRequired: true, rejectionCount: 4 },
      ),
    ).toBeUndefined();
  });
});
