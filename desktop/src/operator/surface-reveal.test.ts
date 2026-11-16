import { describe, expect, it } from "vitest";
import type { OperatorMessage, OperatorSnapshot } from "./contract";
import { createSurfaceRevealState, hasSurfaceToolCall } from "./surface-reveal";

const message = (toolName: string): OperatorMessage => ({
  role: "tool",
  toolName,
  content: "",
  createdAt: "now",
  status: "running",
});
const snapshot = (
  messages: OperatorMessage[],
  subagents: OperatorSnapshot["subagents"] = [],
) => ({ messages, subagents }) as OperatorSnapshot;
const memoryStorage = () => {
  const values = new Map<string, string>();
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => {
      values.set(key, value);
    },
  };
};

describe("attack surface automatic reveal", () => {
  it("reacts to a running topology call from the operator or a recon subagent", () => {
    expect(hasSurfaceToolCall(snapshot([message("document_boundary")]))).toBe(
      true,
    );
    expect(
      hasSurfaceToolCall(
        snapshot(
          [],
          [
            {
              id: "recon",
              name: "Recon",
              status: "running",
              input: {},
              messages: [message("document_flow")],
            },
          ],
        ),
      ),
    ).toBe(true);
    expect(hasSurfaceToolCall(snapshot([message("execute_command")]))).toBe(
      false,
    );
    expect(
      hasSurfaceToolCall(
        snapshot([{ ...message("document_flow"), role: "assistant" }]),
      ),
    ).toBe(false);
  });

  it("opens once per session, including after the view or app is recreated", () => {
    const storage = memoryStorage();
    const reveal = createSurfaceRevealState(() => storage);
    expect(reveal.claim("one")).toBe(true);
    expect(reveal.claim("one")).toBe(false);
    expect(createSurfaceRevealState(() => storage).claim("one")).toBe(false);
    expect(reveal.claim("two")).toBe(true);
  });

  it("does not reopen after a manually opened sidebar was closed before recon", () => {
    const reveal = createSurfaceRevealState(memoryStorage);
    reveal.markShown("manual");
    expect(reveal.claim("manual")).toBe(false);
  });

  it("still opens only once when webview storage is unavailable", () => {
    const reveal = createSurfaceRevealState(() => {
      throw new Error("Storage unavailable");
    });
    expect(reveal.claim("one")).toBe(true);
    expect(reveal.claim("one")).toBe(false);
  });
});
