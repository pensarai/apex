import { describe, expect, it } from "vitest";
import type { BrowserBackend } from "../../../tools/backends/types";
import {
  BROWSER_SNAPSHOT_MAX_CHARS,
  capBrowserSnapshot,
} from "./browserSnapshotText";
import { createBackendBrowserToolFactories } from "./browserToolFactories";

function line(role: string, name: string): string {
  return `[ref=e0] ${role} "${name}"`;
}

describe("capBrowserSnapshot", () => {
  it("returns a snapshot that already fits unchanged", () => {
    const snapshot = `${line("textbox", "Email")}\n${line("button", "Continue")}`;
    expect(capBrowserSnapshot(snapshot)).toBe(snapshot);
  });

  it("keeps a late login control and drops generic nodes that fill the tree", () => {
    const generic = Array.from({ length: 2_000 }, (_, i) =>
      line("generic", `hidden node ${i} ${"x".repeat(40)}`),
    );
    const email = '[ref=e900] textbox "Email"';
    const password = '[ref=e901] textbox "Password"';
    const submit = '[ref=e902] button "Continue"';
    const snapshot = [...generic, email, password, submit].join("\n");
    expect(snapshot.length).toBeGreaterThan(BROWSER_SNAPSHOT_MAX_CHARS);

    const capped = capBrowserSnapshot(snapshot);
    expect(capped.length).toBeLessThanOrEqual(BROWSER_SNAPSHOT_MAX_CHARS);
    expect(capped).toContain(email);
    expect(capped).toContain(password);
    expect(capped).toContain(submit);
    expect(capped).toContain("lines omitted");
    expect(capped).not.toContain("hidden node 1999");
  });

  it("truncates a single line longer than the cap", () => {
    const snapshot = line("generic", "y".repeat(BROWSER_SNAPSHOT_MAX_CHARS));
    const capped = capBrowserSnapshot(snapshot);
    expect(capped.length).toBeLessThanOrEqual(BROWSER_SNAPSHOT_MAX_CHARS);
    expect(capped).toContain("snapshot truncated");
  });

  it("caps the snapshot the tool returns to the model", async () => {
    const generic = Array.from({ length: 2_000 }, (_, i) =>
      line("generic", `noise ${i}`),
    );
    const password = '[ref=e2] textbox "Password"';
    const snapshot = [...generic, password].join("\n");
    const backend = {
      snapshot: async () => ({ success: true, snapshot }),
    } as BrowserBackend;
    const tools = createBackendBrowserToolFactories(backend, {
      targetUrl: "https://app.example",
    });
    const result = (await tools
      .browser_snapshot()
      .execute?.(
        { toolCallDescription: "find the password field" },
        { toolCallId: "t", messages: [], abortSignal: undefined as never },
      )) as { snapshot?: string };
    expect(result.snapshot?.length).toBeLessThanOrEqual(
      BROWSER_SNAPSHOT_MAX_CHARS,
    );
    expect(result.snapshot).toContain(password);
  });
});
