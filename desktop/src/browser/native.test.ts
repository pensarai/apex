import type { BrowserView } from "electrobun/bun";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CdpConnection } from "./cdp";
import { nativeBrowserBridge } from "./native";

describe("native browser ownership", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });
  it("rejects unrelated, trusted and foreign-partition views before connecting", async () => {
    const view = {
      windowId: 1,
      renderer: "cef",
      sandbox: true,
      partition: "ours",
      url: "about:blank#ours",
      isRemoved: false,
    };
    const expected = { partition: "ours", url: view.url };
    const connect = vi.spyOn(CdpConnection, "connect");
    for (const patch of [
      { windowId: 2 },
      { sandbox: false },
      { partition: "other" },
      { renderer: "native" },
      { url: "about:blank#other" },
      { isRemoved: true },
    ]) {
      const bridge = nativeBrowserBridge({
        windowId: () => 1,
        getView: () => ({ ...view, ...patch }) as BrowserView,
      });
      await expect(bridge.resolve(2, expected)).rejects.toThrow(
        "does not belong",
      );
    }
    expect(connect).not.toHaveBeenCalled();
  });
  it("resolves only the marked tab and releases its discovery connection", async () => {
    const close = vi.fn();
    const send = vi.fn(async () => ({
      targetInfos: [
        {
          targetId: "other",
          browserContextId: "foreign",
          url: "about:blank#other",
        },
        { targetId: "mine", browserContextId: "ours", url: "about:blank#ours" },
      ],
    }));
    vi.spyOn(CdpConnection, "connect").mockResolvedValue({
      send,
      close,
    } as unknown as CdpConnection);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ webSocketDebuggerUrl: "ws://native" })),
    );
    const bridge = nativeBrowserBridge({
      windowId: () => 1,
      getView: () =>
        ({
          windowId: 1,
          renderer: "cef",
          sandbox: true,
          partition: "ours",
          url: "about:blank#ours",
        }) as BrowserView,
    });
    await expect(
      bridge.resolve(2, { partition: "ours", url: "about:blank#ours" }),
    ).resolves.toEqual({
      targetId: "mine",
      contextId: "ours",
      endpoint: "ws://native",
    });
    expect(close).toHaveBeenCalledOnce();
  });
});
