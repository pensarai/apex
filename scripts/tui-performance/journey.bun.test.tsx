import { expect, test } from "bun:test";
import { runTypingJourney } from "./journey";

for (const historySize of [100, 1000]) {
  for (const streamEvery of [0, 4]) {
    test(`typing with ${historySize} messages (stream every ${streamEvery} keys)`, async () => {
      const result = await runTypingJourney({ historySize, streamEvery });
      expect(result.measuredKeys).toBe(36);
      expect(result.typingToCapturedFrameMs.samples).toBe(36);
      expect(result.streamToCapturedFrameMs.samples).toBe(streamEvery ? 9 : 0);
      const budget = streamEvery ? 9 : 0;
      expect(result.work.transcriptTraversals).toBeLessThanOrEqual(budget);
      expect(result.work.messageVisits).toBeLessThanOrEqual(
        budget * (historySize + 1),
      );
    }, 30_000);
  }
}
