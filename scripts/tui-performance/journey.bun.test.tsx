import { expect, test } from "bun:test";
import { runTypingJourney } from "./journey";

for (const streamEvery of [0, 4]) {
  test(`typing with transcript (stream every ${streamEvery} keys)`, async () => {
    const result = await runTypingJourney({ historySize: 100, streamEvery });
    expect(result.measuredKeys).toBe(36);
    expect(result.typingToCapturedFrameMs.samples).toBe(36);
    expect(result.streamToCapturedFrameMs.samples).toBe(streamEvery ? 9 : 0);
    const budget = streamEvery ? 45 : 36;
    expect(result.work.transcriptTraversals).toBeLessThanOrEqual(budget);
    expect(result.work.messageVisits).toBeLessThanOrEqual(budget * 101);
  }, 30_000);
}
