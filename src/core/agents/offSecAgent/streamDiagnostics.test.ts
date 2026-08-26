import { describe, expect, it, vi } from "vitest";
import { responseArgBytes, StreamDiagnostics } from "./streamDiagnostics";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeDiagnostics(overrides?: {
  stallEnabled?: boolean;
  responseDebugEnabled?: boolean;
  inFlightTools?: Map<string, string>;
  responseToolFired?: boolean;
}) {
  const warns: string[] = [];
  const inFlightTools = overrides?.inFlightTools ?? new Map<string, string>();
  const diagnostics = new StreamDiagnostics({
    sessionId: "ses_test",
    subagentId: "sub_1",
    inFlightTools: () => inFlightTools,
    responseToolFired: () => overrides?.responseToolFired ?? false,
    responseToolName: "response",
    stallEnabled: overrides?.stallEnabled ?? false,
    responseDebugEnabled: overrides?.responseDebugEnabled ?? false,
    warn: (m) => warns.push(m),
  });
  return { diagnostics, warns, inFlightTools };
}

// ---------------------------------------------------------------------------
// Stall watchdog
// ---------------------------------------------------------------------------

describe("StreamDiagnostics stall watchdog", () => {
  it("warns when no chunk arrives within the stall window, reporting step/type/in-flight state", () => {
    vi.useFakeTimers();
    try {
      const { diagnostics, warns, inFlightTools } = makeDiagnostics({
        stallEnabled: true,
      });
      inFlightTools.set("tc-1", "response");
      diagnostics.start();

      diagnostics.observeChunk({ type: "start-step" });
      diagnostics.observeChunk({ type: "text-delta", delta: "hi" });

      // 20s warn threshold, 15s tick — the second tick crosses it.
      vi.advanceTimersByTime(15_000);
      expect(warns).toHaveLength(0);
      vi.advanceTimersByTime(15_000);

      expect(warns).toHaveLength(1);
      const warn = warns[0] ?? "";
      expect(warn).toContain("[stream-stall]");
      expect(warn).toContain("session=ses_test");
      expect(warn).toContain("subagent=sub_1");
      expect(warn).toContain("step=0");
      expect(warn).toContain("lastChunkType=text-delta");
      expect(warn).toContain("inFlightTools=response");
      expect(warn).toContain("responseToolFired=false");
    } finally {
      vi.useRealTimers();
    }
  });

  it("stop() clears the interval and is idempotent", () => {
    vi.useFakeTimers();
    try {
      const { diagnostics, warns } = makeDiagnostics({
        stallEnabled: true,
      });
      diagnostics.start();
      diagnostics.stop();
      diagnostics.stop();

      vi.advanceTimersByTime(120_000);
      expect(warns).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("start() is a no-op when the watchdog is disabled", () => {
    vi.useFakeTimers();
    try {
      const { diagnostics, warns } = makeDiagnostics({ stallEnabled: false });
      diagnostics.start();
      vi.advanceTimersByTime(120_000);
      expect(warns).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------
// Stream-gap tracking
// ---------------------------------------------------------------------------

describe("StreamDiagnostics gap tracking", () => {
  it("warns when a chunk arrives after a long silence", () => {
    vi.useFakeTimers();
    try {
      const { diagnostics, warns } = makeDiagnostics({
        stallEnabled: true,
      });
      diagnostics.start();
      diagnostics.observeChunk({ type: "text-delta", delta: "first" });

      vi.advanceTimersByTime(11_000);
      diagnostics.observeChunk({ type: "tool-call", toolCallId: "tc-1" });

      expect(warns).toHaveLength(1);
      expect(warns[0]).toContain("[stream-gap]");
      expect(warns[0]).toContain("recovered after 11s");
      expect(warns[0]).toContain("session=ses_test");
      expect(warns[0]).toContain("chunkType=tool-call");
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not warn for short gaps", () => {
    vi.useFakeTimers();
    try {
      const { diagnostics, warns } = makeDiagnostics({
        stallEnabled: true,
      });
      diagnostics.observeChunk({ type: "text-delta", delta: "a" });
      vi.advanceTimersByTime(5_000);
      diagnostics.observeChunk({ type: "text-delta", delta: "b" });
      expect(warns).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("gap tracking is disabled with the watchdog", () => {
    vi.useFakeTimers();
    try {
      const { diagnostics, warns } = makeDiagnostics({
        stallEnabled: false,
      });
      diagnostics.observeChunk({ type: "text-delta", delta: "a" });
      vi.advanceTimersByTime(60_000);
      diagnostics.observeChunk({ type: "text-delta", delta: "b" });
      expect(warns).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------
// Response-tool tracer
// ---------------------------------------------------------------------------

describe("StreamDiagnostics response-tool tracer", () => {
  it("traces the full response-tool lifecycle with arg-char accumulation", () => {
    const inFlight = new Map<string, string>([["tc-r", "response"]]);
    const { diagnostics, warns } = makeDiagnostics({
      responseDebugEnabled: true,
      inFlightTools: inFlight,
    });

    diagnostics.observeChunk({
      type: "tool-input-start",
      id: "tc-r",
      toolName: "response",
    });
    diagnostics.observeChunk({
      type: "tool-input-delta",
      id: "tc-r",
      delta: '{"summary":',
    });
    diagnostics.observeChunk({
      type: "tool-input-delta",
      id: "tc-r",
      delta: '"x"}',
    });
    diagnostics.observeChunk({ type: "tool-input-end", id: "tc-r" });
    expect(warns.some((w) => w.includes("tool-input-start id=tc-r"))).toBe(
      true,
    );
    expect(
      warns.some((w) => w.includes("tool-input-end id=tc-r argChars=15")),
    ).toBe(true);

    diagnostics.observeChunk({
      type: "tool-call",
      id: "tc-r",
      toolName: "response",
      input: { summary: "x" },
    });
    expect(
      warns.some(
        (w) =>
          w.includes("tool-call id=tc-r") &&
          w.includes("streamedArgChars=15") &&
          w.includes("invalid=false"),
      ),
    ).toBe(true);

    diagnostics.observeChunk({
      type: "tool-result",
      id: "tc-r",
      toolName: "response",
    });
    expect(warns.some((w) => w.includes("tool-result id=tc-r"))).toBe(true);
  });

  it("resolves the tool name via in-flight state when the chunk omits it", () => {
    const inFlight = new Map<string, string>([["tc-r", "response"]]);
    const { diagnostics, warns } = makeDiagnostics({
      responseDebugEnabled: true,
      inFlightTools: inFlight,
    });

    diagnostics.observeChunk({ type: "tool-error", id: "tc-r", error: "boom" });

    expect(
      warns.some(
        (w) =>
          w.includes("tool-error id=tc-r") &&
          w.includes("stillInFlight=true") &&
          w.includes("error=boom"),
      ),
    ).toBe(true);
  });

  it("ignores non-response tools and stays silent when disabled", () => {
    const silent = makeDiagnostics({ responseDebugEnabled: false });
    silent.diagnostics.observeChunk({
      type: "tool-call",
      id: "tc-1",
      toolName: "response",
    });
    expect(silent.warns).toHaveLength(0);

    const enabled = makeDiagnostics({ responseDebugEnabled: true });
    enabled.diagnostics.observeChunk({
      type: "tool-call",
      id: "tc-1",
      toolName: "execute_command",
    });
    enabled.diagnostics.observeChunk({
      type: "tool-result",
      id: "tc-1",
      toolName: "execute_command",
    });
    expect(enabled.warns).toHaveLength(0);
  });

  it("logSurfacedToolError and logClosingInFlightTool only trace the response tool", () => {
    const { diagnostics, warns } = makeDiagnostics({
      responseDebugEnabled: true,
    });

    diagnostics.logSurfacedToolError({
      toolCallId: "tc-1",
      toolName: "execute_command",
      message: "failed",
      streamedArgChars: 5,
      truncated: false,
    });
    diagnostics.logClosingInFlightTool({
      toolCallId: "tc-2",
      toolName: "execute_command",
      truncated: false,
    });
    expect(warns).toHaveLength(0);

    diagnostics.logSurfacedToolError({
      toolCallId: "tc-r",
      toolName: "response",
      message: "args never completed",
      streamedArgChars: 42,
      finishReason: "length",
      truncated: true,
    });
    diagnostics.logClosingInFlightTool({
      toolCallId: "tc-r2",
      toolName: "response",
      finishReason: "stop",
      truncated: false,
    });
    expect(warns).toHaveLength(2);
    expect(warns[0]).toContain("tool-error SURFACED id=tc-r");
    expect(warns[0]).toContain("finishReason=length");
    expect(warns[0]).toContain("outputTokenTruncated=true");
    expect(warns[1]).toContain(
      'CLOSING response as "did not complete" id=tc-r2',
    );
  });
});

// ---------------------------------------------------------------------------
// responseArgBytes
// ---------------------------------------------------------------------------

describe("responseArgBytes", () => {
  it("measures strings, objects, and edge cases", () => {
    expect(responseArgBytes(null)).toBe(0);
    expect(responseArgBytes(undefined)).toBe(0);
    expect(responseArgBytes("abc")).toBe(3);
    expect(responseArgBytes({ a: 1 })).toBe(JSON.stringify({ a: 1 }).length);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(responseArgBytes(cyclic)).toBe(-1);
  });
});
