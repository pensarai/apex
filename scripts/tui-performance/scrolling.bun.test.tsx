import { expect, test } from "bun:test";
import { runScrollingJourney } from "./scrolling";

for (const historySize of [100, 1000]) {
  for (const streamEvery of [0, 4]) {
    test(`wheel scrolling through ${historySize} messages (stream every ${streamEvery}) preserves position and follow`, async () => {
      const result = await runScrollingJourney(historySize, streamEvery);
      const updates = streamEvery === 0 ? 0 : 30;
      expect(result.wheelToFrameMs.samples).toBe(120 - updates);
      expect(result.streamAndWheelToFrameMs.samples).toBe(updates);
      expect(result.work.transcriptTraversals).toBe(updates);
      expect(result.growthRows).toBe(updates * 2);
      expect(result.work.layoutReads).toBeLessThan(120 * (historySize + 100));
    });
  }
}

test("a restored reply taller than the viewport remains scrollable", async () => {
  const reply = `${"Restored paragraph.\n\n".repeat(60)}LIVE_START`;
  const result = await runScrollingJourney(100, 4, reply);
  expect(result.growthRows).toBe(60);
});
