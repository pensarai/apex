import { describe, expect, it, vi } from "vitest";
import { FAST_STRIKE_EXCLUDED_TOOL_NAMES } from "../agents/offSecAgent/tools";
import {
  buildFastStrikeRecoveryDossier,
  FAST_STRIKE_SYSTEM_PROMPT,
  minimumVerifiedLayers,
  normalizeFastStrikeOutcome,
  rejectUnverifiedFastStrikeResponse,
  requestsExactFlag,
  requiredEdgeVerificationDimensions,
  requiredObjectiveVerificationDimensions,
  resolveFastStrikeLaneTimeoutMs,
  runCompetitiveLanes,
} from "./fastStrike";

type Outcome = { solved: boolean; lane: number };

describe("runCompetitiveLanes", () => {
  it("reserves recovery time for competitive lanes while leaving one lane unlimited", () => {
    expect(resolveFastStrikeLaneTimeoutMs(1)).toBeUndefined();
    expect(resolveFastStrikeLaneTimeoutMs(2)).toBe(30 * 60 * 1000);
    expect(resolveFastStrikeLaneTimeoutMs(3)).toBe(30 * 60 * 1000);
    expect(resolveFastStrikeLaneTimeoutMs(3, 900_000)).toBe(900_000);
  });

  it("returns the first success and cancels the remaining lane", async () => {
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
      (outcome) => outcome.solved,
    );

    resolveWinner({ solved: true, lane: 2 });
    await expect(resultPromise).resolves.toEqual({ solved: true, lane: 2 });
    expect(loserAborted).toHaveBeenCalledOnce();
  });

  it("returns an honest unsolved result after every lane settles", async () => {
    const result = await runCompetitiveLanes<Outcome>(
      [
        async () => ({ solved: false, lane: 1 }),
        async () => ({ solved: false, lane: 2 }),
      ],
      (outcome) => outcome.solved,
    );

    expect(result.solved).toBe(false);
    expect([1, 2]).toContain(result.lane);
  });

  it("preserves a completed lane when a sibling fails", async () => {
    const result = await runCompetitiveLanes<Outcome>(
      [
        async () => {
          throw new Error("provider failed");
        },
        async () => ({ solved: false, lane: 2 }),
      ],
      (outcome) => outcome.solved,
    );

    expect(result).toEqual({ solved: false, lane: 2 });
  });
});

describe("normalizeFastStrikeOutcome", () => {
  it("turns a missing lane response into an unsolved settlement", () => {
    expect(normalizeFastStrikeOutcome(undefined)).toEqual({
      solved: false,
      summary:
        "Lane ended without a valid accepted response; sibling lanes may continue.",
    });
  });

  it("preserves a valid accepted response", () => {
    expect(
      normalizeFastStrikeOutcome({
        solved: true,
        summary: "captured evidence",
      }),
    ).toEqual({ solved: true, summary: "captured evidence" });
  });

  it("downgrades an unverified exact-flag success before lane settlement", () => {
    expect(
      normalizeFastStrikeOutcome(
        { solved: true, summary: "Reached the secrets service" },
        { exactFlagRequired: true },
      ),
    ).toEqual({
      solved: false,
      summary:
        "Lane claimed success without the required literal FLAG{...} proof. Reached the secrets service",
    });
  });

  it("preserves a solved outcome with literal exact-flag proof", () => {
    expect(
      normalizeFastStrikeOutcome(
        { solved: true, summary: "Recovered FLAG{literal-proof}" },
        { exactFlagRequired: true },
      ),
    ).toEqual({
      solved: true,
      summary: "Recovered FLAG{literal-proof}",
    });
  });
});

describe("buildFastStrikeRecoveryDossier", () => {
  it("preserves every settled lane handoff in lane order", () => {
    expect(
      buildFastStrikeRecoveryDossier([
        { solved: false, summary: "confirmed SSRF" },
        undefined,
        { solved: false, summary: "found a signed callback" },
      ]),
    ).toBe(
      "Lane 1 (solved=false):\nconfirmed SSRF\n\n---\n\nLane 3 (solved=false):\nfound a signed callback",
    );
  });

  it("provides a fresh-observation fallback without structured handoffs", () => {
    expect(buildFastStrikeRecoveryDossier([undefined])).toContain(
      "fresh observations",
    );
  });

  it("bounds each handoff before injecting it into recovery context", () => {
    const dossier = buildFastStrikeRecoveryDossier([
      { solved: false, summary: "x".repeat(7000) },
    ]);
    expect(dossier.length).toBeLessThan(6100);
  });
});

describe("fast-strike missing-intermediary guidance", () => {
  it("keeps service discovery explicitly bounded and target-local", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("ports 1-10000");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("at most 100 probes/second");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("only against that host");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("same-host listener");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "at most 12 internal host:port",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "negative host-port inventory does not disprove application-internal DNS",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "do not scan external DNS or the public Internet",
    );
  });

  it("requires target-side verification across multi-layer objectives", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "promote each named or subsequently observed relevant layer",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "a final secret does not prove the intermediate controls",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("minimum target-side request");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "process environment, injected-shell output, debug output",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "protocol-native final read against the named sink",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "a before/after state read proving the safety constraint",
    );
  });

  it("bounds custom authentication canonicalization recovery", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "matrix of at most 24 canonicalizations",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "identity, credential-scope date, HTTP method, and path",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("colon and newline delimiters");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("never guess keys or secrets");
  });

  it("dispatches observed high-friction classes to bounded canonical families", () => {
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "document renderers, HTML, CSS, SVG",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "duplicate-parameter, content-type, and browser-reparse variants",
    );
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain("serverless event adapters");
    expect(FAST_STRIKE_SYSTEM_PROMPT).toContain(
      "correlation-labeled concurrency",
    );
  });
});

describe("fast-strike tool envelope", () => {
  it("omits endpoint-analysis fanout while preserving operational contracts", () => {
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).toContain("document_app");
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).toContain("document_endpoint");
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).not.toContain(
      "document_vulnerability",
    );
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).not.toContain("checkpoint_state");
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).not.toContain("browser_screenshot");
  });
});

describe("fast-strike response verification", () => {
  it("detects exact-flag objectives without treating placeholders as evidence", () => {
    expect(requestsExactFlag("Find the flag (format: FLAG{...})")).toBe(true);
    expect(requestsExactFlag("Return the exact flag value")).toBe(true);
    expect(requestsExactFlag("Confirm account takeover")).toBe(false);

    expect(
      rejectUnverifiedFastStrikeResponse(
        { solved: true, summary: "Recovered FLAG{...}" },
        { exactFlagRequired: true, rejectionCount: 0 },
      )?.message,
    ).toContain("does not contain the exact recovered");
  });

  it("accepts a solved exact-flag response only when the literal value is present", () => {
    expect(
      rejectUnverifiedFastStrikeResponse(
        { solved: true, summary: "Recovered FLAG{literal-value}" },
        { exactFlagRequired: true, rejectionCount: 0 },
      ),
    ).toBeUndefined();
  });

  it("requires a concrete verification ledger for explicit multi-layer assessments", () => {
    expect(
      minimumVerifiedLayers(
        "Assess an application protected by multiple defensive layers",
      ),
    ).toBe(6);
    expect(
      minimumVerifiedLayers("Assess a Kubernetes control-plane environment"),
    ).toBe(6);
    expect(
      minimumVerifiedLayers("Recover the protected secret"),
    ).toBeUndefined();
    expect(minimumVerifiedLayers("Return the exact flag value")).toBe(2);
    expect(
      requiredEdgeVerificationDimensions(
        "Assess an application protected by multiple defensive layers",
      ),
    ).toEqual(["forwarding-identity", "transport-framing", "protocol-version"]);
    expect(
      requiredEdgeVerificationDimensions(
        "Assess a Kubernetes control-plane environment",
      ),
    ).toBeUndefined();
    expect(
      requiredObjectiveVerificationDimensions(
        "Take control of the privileged account and recover the flag held in telemetry storage",
      ),
    ).toEqual(["telemetry", "storage", "authentication", "authorization"]);

    expect(
      rejectUnverifiedFastStrikeResponse(
        {
          solved: true,
          summary: "Recovered FLAG{literal-value}",
          verifiedLayers: [
            {
              dimension: "application",
              layer: "gateway",
              targetSideRequest: "GET /gateway",
              observedResult: "200",
            },
            {
              dimension: "application",
              layer: " Gateway ",
              targetSideRequest: "GET /gateway/again",
              observedResult: "200",
            },
          ],
        },
        {
          exactFlagRequired: true,
          minimumVerifiedLayers: 6,
          rejectionCount: 0,
        },
      )?.message,
    ).toContain("only 1 of at least 6");
  });

  it("requires edge-parser diversity for explicit layered defenses", () => {
    const verifiedLayers = Array.from({ length: 6 }, (_, index) => ({
      dimension: "application" as const,
      layer: `application control ${index}`,
      targetSideRequest: `GET /control/${index}`,
      observedResult: "HTTP 200",
    }));
    const requiredDimensions = [
      "forwarding-identity",
      "transport-framing",
      "protocol-version",
    ] as const;

    expect(
      rejectUnverifiedFastStrikeResponse(
        {
          solved: true,
          summary: "Recovered FLAG{literal-value}",
          verifiedLayers,
        },
        {
          exactFlagRequired: true,
          minimumVerifiedLayers: 6,
          requiredDimensions,
          rejectionCount: 0,
        },
      )?.message,
    ).toContain("forwarding-identity, transport-framing, protocol-version");

    expect(
      normalizeFastStrikeOutcome(
        {
          solved: true,
          summary: "Recovered FLAG{literal-value}",
          verifiedLayers,
        },
        {
          exactFlagRequired: true,
          minimumVerifiedLayers: 6,
          requiredDimensions,
        },
      ),
    ).toMatchObject({
      solved: false,
      summary: expect.stringContaining("transport-framing"),
    });

    const completeLedger = verifiedLayers.map((entry, index) => ({
      ...entry,
      dimension: requiredDimensions[index] ?? entry.dimension,
    }));
    expect(
      rejectUnverifiedFastStrikeResponse(
        {
          solved: true,
          summary: "Recovered FLAG{literal-value}",
          verifiedLayers: completeLedger,
        },
        {
          exactFlagRequired: true,
          minimumVerifiedLayers: 6,
          requiredDimensions,
          rejectionCount: 0,
        },
      ),
    ).toBeUndefined();
  });

  it("downgrades multi-layer success after the bounded response guard expires", () => {
    expect(
      normalizeFastStrikeOutcome(
        {
          solved: true,
          summary: "Recovered FLAG{literal-value}",
          verifiedLayers: [],
        },
        { exactFlagRequired: true, minimumVerifiedLayers: 6 },
      ),
    ).toMatchObject({
      solved: false,
      summary: expect.stringContaining("0/6"),
    });
  });

  it("preserves the bounded four-rejection recovery policy", () => {
    expect(
      rejectUnverifiedFastStrikeResponse(
        { solved: false, summary: "No result" },
        { exactFlagRequired: false, rejectionCount: 0 },
      )?.message,
    ).toContain("still unsolved");
    expect(
      rejectUnverifiedFastStrikeResponse(
        { solved: false, summary: "No result" },
        { exactFlagRequired: false, rejectionCount: 3 },
      )?.message,
    ).toContain("still unsolved");
    expect(
      rejectUnverifiedFastStrikeResponse(
        { solved: false, summary: "No result" },
        { exactFlagRequired: false, rejectionCount: 4 },
      ),
    ).toBeUndefined();
  });
});
