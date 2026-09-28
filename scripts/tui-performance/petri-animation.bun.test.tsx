import { expect, test } from "bun:test";
import {
  runPetriIdleJourney,
  runPetriInputResourceJourney,
  runPetriMountWhileBlurredJourney,
  runPetriRendererIndependenceJourney,
  runPetriUnmountedFocusChangeJourney,
} from "./petri-animation";

test("idle animation: one update per tick, frozen while blurred, resumes on refocus", async () => {
  const result = await runPetriIdleJourney();
  expect(result.commitsPerTick).toBe(1);
  expect(result.blurredUpdates).toBe(0);
  expect(result.pendingTimersAfterDestroy).toBe(0);
}, 30_000);

test("idle animation mounted while blurred stays frozen until refocus", async () => {
  const result = await runPetriMountWhileBlurredJourney();
  expect(result.blurredUpdates).toBe(0);
}, 30_000);

test("idle animation captures focus changes while unmounted", async () => {
  const result = await runPetriUnmountedFocusChangeJourney();
  expect(result.remountedUpdates).toBe(1);
}, 30_000);

test("idle animation focus state never crosses renderer lifetimes", async () => {
  await runPetriRendererIndependenceJourney();
}, 30_000);

test("idle animation keeps prompt typing, caret, and submit working while owning only its resources", async () => {
  const result = await runPetriInputResourceJourney();
  expect(result.steps).toBe(4);
  expect(result.submissions).toEqual(["aXb"]);
  expect(result.pendingTimersAfterDestroy).toBe(0);
}, 30_000);
