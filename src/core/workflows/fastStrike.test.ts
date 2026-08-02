import { describe, expect, it, vi } from "vitest";
import {
  buildFastStrikeRecoveryDossier,
  FAST_STRIKE_SYSTEM_PROMPT,
  normalizeFastStrikeOutcome,
  rejectUnverifiedFastStrikeResponse,
  requestsExactFlag,
  runCompetitiveLanes,
} from "./fastStrike";

type Outcome = { solved: boolean; lane: number };

describe("runCompetitiveLanes", () => {
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

  it("preserves the bounded two-rejection recovery policy", () => {
    expect(
      rejectUnverifiedFastStrikeResponse(
        { solved: false, summary: "No result" },
        { exactFlagRequired: false, rejectionCount: 0 },
      )?.message,
    ).toContain("still unsolved");
    expect(
      rejectUnverifiedFastStrikeResponse(
        { solved: false, summary: "No result" },
        { exactFlagRequired: false, rejectionCount: 2 },
      ),
    ).toBeUndefined();
  });
});
