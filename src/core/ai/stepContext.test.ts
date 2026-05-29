import { describe, expect, it } from "vitest";
import { runWithStepContext, takeStepContext } from "./ai";

describe("per-run step counter", () => {
  it("hands out stepSeq 0..N-1 within a run, tagged with the sessionId", () => {
    const seqs = runWithStepContext({ sessionId: "ses_root" }, () => {
      const out: Array<{ sessionId?: string; stepSeq?: number }> = [];
      for (let i = 0; i < 5; i++) {
        const ctx = takeStepContext();
        out.push(ctx!);
      }
      return out;
    });

    expect(seqs.map((c) => c.stepSeq)).toEqual([0, 1, 2, 3, 4]);
    expect(seqs.every((c) => c.sessionId === "ses_root")).toBe(true);
  });

  it("continues monotonically across a resumed run via seedStepSeq", () => {
    // A resumed run with M=3 prior assistant messages seeds the counter at 3.
    const seqs = runWithStepContext(
      { sessionId: "ses_resumed", seedStepSeq: 3 },
      () => {
        const out: number[] = [];
        for (let i = 0; i < 3; i++) out.push(takeStepContext()!.stepSeq!);
        return out;
      },
    );
    expect(seqs).toEqual([3, 4, 5]);
  });

  it("returns undefined outside any run context (backward compatible)", () => {
    expect(takeStepContext()).toBeUndefined();
  });

  it("isolates concurrent runs — each gets its own counter", async () => {
    const runA = new Promise<number[]>((resolve) => {
      runWithStepContext({ sessionId: "ses_a" }, async () => {
        const out: number[] = [];
        out.push(takeStepContext()!.stepSeq!);
        await Promise.resolve();
        out.push(takeStepContext()!.stepSeq!);
        resolve(out);
      });
    });
    const runB = new Promise<number[]>((resolve) => {
      runWithStepContext({ sessionId: "ses_b" }, async () => {
        const out: number[] = [];
        out.push(takeStepContext()!.stepSeq!);
        await Promise.resolve();
        out.push(takeStepContext()!.stepSeq!);
        resolve(out);
      });
    });

    const [a, b] = await Promise.all([runA, runB]);
    // Both runs count independently from 0 — no cross-contamination.
    expect(a).toEqual([0, 1]);
    expect(b).toEqual([0, 1]);
  });
});
