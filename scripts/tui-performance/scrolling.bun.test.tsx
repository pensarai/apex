import { expect, test } from "bun:test";
import { runScrollingJourney } from "./scrolling";

for (const historySize of [100, 1000]) {
  test(`wheel scrolling through ${historySize} messages preserves position and follow`, async () => {
    const result = await runScrollingJourney(historySize, 0);
    expect(result.wheelToFrameMs.samples).toBe(120);
    expect(result.work.transcriptTraversals).toBe(0);
    expect(result.work.layoutReads).toBeLessThan(120 * (historySize + 100));
  });
}
