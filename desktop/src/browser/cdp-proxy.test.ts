import { afterEach, describe, expect, it, vi } from "vitest";
import { createSessionCdpProxy } from "./cdp-proxy";

describe("session browser isolation", () => {
  afterEach(() => vi.unstubAllGlobals());
  function fixture() {
    class Socket {
      static OPEN = 1;
      static CONNECTING = 0;
      static last: Socket;
      readyState = 1;
      send = vi.fn();
      close = vi.fn();
      onmessage: undefined | ((event: { data: string }) => void);
      constructor() {
        Socket.last = this;
      }
    }
    const stop = vi.fn();
    const serve = vi.fn((_options: unknown) => ({ port: 1234, stop }));
    vi.stubGlobal("Bun", { serve });
    vi.stubGlobal("WebSocket", Socket);
    const createTarget = vi.fn(async () => "created");
    const closeTarget = vi.fn();
    const proxy = createSessionCdpProxy({
      endpoint: "ws://browser",
      contextId: "ours",
      createTarget,
      closeTarget,
    });
    const options = vi.mocked(serve).mock.calls[0]?.[0] as unknown as {
      fetch: (
        request: Request,
        server: {
          upgrade: (request: Request, options: { data: unknown }) => boolean;
        },
      ) => void;
      websocket: {
        open: (client: unknown) => void;
        message: (client: unknown, message: string) => Promise<void>;
        close: (client: unknown) => void;
      };
    };
    let data: unknown;
    options.fetch(new Request(proxy.endpoint.replace("ws:", "http:")), {
      upgrade: (_request, options) => {
        data = options.data;
        return true;
      },
    });
    const upstream = Socket.last;
    const client = { data, send: vi.fn(), close: vi.fn() };
    options.websocket.open(client);
    const event = (message: unknown) =>
      upstream.onmessage?.({ data: JSON.stringify(message) });
    const send = (message: unknown) =>
      options.websocket.message(client, JSON.stringify(message));
    const responses = () =>
      client.send.mock.calls.map(([value]) => JSON.parse(value));
    return {
      proxy,
      upstream,
      client,
      event,
      send,
      responses,
      createTarget,
      closeTarget,
      stop,
    };
  }
  it("filters target discovery and blocks access to another session or browser-wide control", async () => {
    const f = fixture();
    await f.send({ id: 1, method: "Target.getTargets" });
    f.event({
      id: 1,
      result: {
        targetInfos: [
          { targetId: "mine", browserContextId: "ours", type: "page" },
          { targetId: "other", browserContextId: "theirs", type: "page" },
        ],
      },
    });
    expect(
      f
        .responses()[0]
        .result.targetInfos.map((t: { targetId: string }) => t.targetId),
    ).toEqual(["mine"]);
    f.event({
      method: "Target.targetCreated",
      params: {
        targetInfo: {
          targetId: "secret",
          browserContextId: "theirs",
          type: "page",
        },
      },
    });
    expect(f.client.send).toHaveBeenCalledTimes(1);
    for (const command of [
      { method: "Target.attachToTarget", params: { targetId: "other" } },
      { method: "Target.createBrowserContext" },
      { method: "Target.attachToBrowserTarget" },
      { method: "Browser.close" },
      { method: "Browser.setWindowBounds", params: { windowId: 1 } },
      {
        method: "Runtime.evaluate",
        sessionId: "foreign",
        params: { expression: "1" },
      },
    ]) {
      await f.send({ id: 2, ...command });
      expect(f.responses().at(-1).error.message).toContain("outside");
    }
    expect(f.upstream.send).toHaveBeenCalledTimes(1);
    f.proxy.close();
  });
  it("presents CEF's provisional native target as a page so Playwright keeps it attached", () => {
    const f = fixture();
    f.event({
      method: "Target.attachedToTarget",
      params: {
        targetInfo: {
          targetId: "new-native",
          browserContextId: "ours",
          type: "other",
          url: "",
        },
        sessionId: "new-session",
      },
    });
    expect(f.responses()[0].params.targetInfo.type).toBe("page");
    f.proxy.close();
  });
  it("closes tabs through the native owner and discards closed page sessions", async () => {
    const f = fixture();
    for (const id of ["first", "second"])
      f.event({
        method: "Target.attachedToTarget",
        params: {
          targetInfo: { targetId: id, browserContextId: "ours", type: "page" },
          sessionId: `${id}-session`,
        },
      });
    await f.send({
      id: 1,
      method: "Target.closeTarget",
      params: { targetId: "first" },
    });
    expect(f.closeTarget).toHaveBeenCalledWith("first");
    expect(f.upstream.send).not.toHaveBeenCalled();
    f.event({
      method: "Target.targetDestroyed",
      params: { targetId: "first" },
    });
    await f.send({ id: 2, method: "Storage.getCookies" });
    expect(JSON.parse(f.upstream.send.mock.calls.at(-1)?.[0]).sessionId).toBe(
      "second-session",
    );
    await f.send({
      id: 3,
      method: "Browser.setWindowBounds",
      sessionId: "second-session",
    });
    expect(f.responses().at(-1).error.message).toContain("outside");
    f.proxy.close();
  });
  it("routes cookie operations through an owned page and keeps new tabs native", async () => {
    const f = fixture();
    f.event({
      method: "Target.attachedToTarget",
      params: {
        targetInfo: {
          targetId: "mine",
          browserContextId: "ours",
          type: "page",
        },
        sessionId: "page-session",
      },
    });
    await f.send({ id: 1, method: "Storage.getCookies" });
    expect(JSON.parse(f.upstream.send.mock.calls.at(-1)?.[0])).toMatchObject({
      method: "Network.getAllCookies",
      sessionId: "page-session",
    });
    f.event({
      id: 1,
      sessionId: "page-session",
      result: { cookies: [{ name: "owned" }] },
    });
    expect(f.responses().at(-1)).toEqual({
      id: 1,
      result: { cookies: [{ name: "owned" }] },
    });
    const creating = f.send({
      id: 2,
      method: "Target.createTarget",
      params: { url: "https://example.test" },
    });
    await vi.waitFor(() =>
      expect(f.upstream.send.mock.calls.at(-1)?.[0]).toContain(
        "Target.attachToTarget",
      ),
    );
    const attach = JSON.parse(f.upstream.send.mock.calls.at(-1)?.[0]);
    f.event({
      method: "Target.attachedToTarget",
      params: {
        targetInfo: {
          targetId: "created",
          browserContextId: "ours",
          type: "page",
        },
        sessionId: "new-page",
      },
    });
    f.event({ id: attach.id, result: { sessionId: "new-page" } });
    await creating;
    expect(f.createTarget).toHaveBeenCalledWith("https://example.test");
    expect(f.responses().at(-1)).toEqual({
      id: 2,
      result: { targetId: "created" },
    });
    f.proxy.close();
    expect(f.upstream.close).toHaveBeenCalled();
    expect(f.stop).toHaveBeenCalledWith(true);
  });
});
