import { afterEach, describe, expect, it } from "vitest";
import { runWithAiPayloadCapture, shouldRecordAiPayloads } from "./index";
import { createAiTelemetrySettings } from "./telemetry";

afterEach(() => {
  process.env.AI_TRACE_RECORD_PAYLOADS = undefined;
});

describe("runWithAiPayloadCapture", () => {
  it("falls back to the env when no run-scoped override is set", () => {
    process.env.AI_TRACE_RECORD_PAYLOADS = undefined;
    expect(shouldRecordAiPayloads()).toBe(false);
    process.env.AI_TRACE_RECORD_PAYLOADS = "true";
    expect(shouldRecordAiPayloads()).toBe(true);
  });

  it("enables capture inside the run even when the env is unset", () => {
    process.env.AI_TRACE_RECORD_PAYLOADS = undefined;
    runWithAiPayloadCapture(true, () => {
      expect(shouldRecordAiPayloads()).toBe(true);
      const settings = createAiTelemetrySettings({
        operation: "apex.agent.stream",
      });
      expect(settings.recordInputs).toBe(true);
      expect(settings.recordOutputs).toBe(true);
    });
    // Override does not leak past the run.
    expect(shouldRecordAiPayloads()).toBe(false);
  });

  it("disables capture inside the run even when the env forces it on", () => {
    process.env.AI_TRACE_RECORD_PAYLOADS = "true";
    runWithAiPayloadCapture(false, () => {
      expect(shouldRecordAiPayloads()).toBe(false);
      const settings = createAiTelemetrySettings({
        operation: "apex.structured.generate",
      });
      expect(settings.recordInputs).toBe(false);
      expect(settings.recordOutputs).toBe(false);
    });
    expect(shouldRecordAiPayloads()).toBe(true);
  });

  it("isolates concurrent runs across awaits (multi-tenant safety)", async () => {
    process.env.AI_TRACE_RECORD_PAYLOADS = undefined;
    const readAfterTick = (enabled: boolean) =>
      runWithAiPayloadCapture(enabled, async () => {
        await Promise.resolve();
        return shouldRecordAiPayloads();
      });

    const [on, off] = await Promise.all([
      readAfterTick(true),
      readAfterTick(false),
    ]);
    expect(on).toBe(true);
    expect(off).toBe(false);
  });
});
