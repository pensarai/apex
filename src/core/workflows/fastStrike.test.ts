import { describe, expect, it, vi } from "vitest";
import { normalizeFastStrikeOutcome, runCompetitiveLanes } from "./fastStrike";

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
});
