import { afterEach, describe, expect, it, vi } from "vitest";
import { CdpConnection } from "./cdp";

class Socket extends EventTarget {
  static OPEN = 1;
  static last: Socket;
  readyState = 1;
  onopen: null | (() => void) = null;
  onmessage: null | ((event: { data: string }) => void) = null;
  onclose: null | (() => void) = null;
  onerror: null | (() => void) = null;
  sent: { id: number; method: string; sessionId?: string }[] = [];
  constructor() {
    super();
    Socket.last = this;
    queueMicrotask(() => this.onopen?.());
  }
  send(value: string) {
    this.sent.push(JSON.parse(value));
  }
  close() {
    this.readyState = 3;
    this.onclose?.();
  }
  reply(value: unknown) {
    this.onmessage?.({ data: JSON.stringify(value) });
  }
}
describe("native browser control connection", () => {
  afterEach(() => vi.unstubAllGlobals());
  it("matches concurrent command responses and forwards page events", async () => {
    vi.stubGlobal("WebSocket", Socket);
    const event = vi.fn();
    const connection = await CdpConnection.connect("ws://fixture", event);
    const first = connection.send(
      "Page.navigate",
      { url: "https://example.test" },
      "page",
    );
    const second = connection.send("Page.reload", {}, "page");
    expect(Socket.last.sent.map((command) => command.sessionId)).toEqual([
      "page",
      "page",
    ]);
    Socket.last.reply({ id: 2, error: { message: "Reload failed" } });
    await expect(second).rejects.toThrow("Reload failed");
    Socket.last.reply({
      method: "Page.domContentEventFired",
      sessionId: "page",
      params: {},
    });
    expect(event).toHaveBeenCalledWith({
      method: "Page.domContentEventFired",
      sessionId: "page",
      params: {},
    });
    Socket.last.reply({ id: 1, result: { frameId: "main" } });
    expect(await first).toEqual({ frameId: "main" });
    connection.close();
  });
  it("rejects pending and future work when disconnected", async () => {
    vi.stubGlobal("WebSocket", Socket);
    const connection = await CdpConnection.connect("ws://fixture");
    const pending = connection.send("Page.navigate");
    connection.close();
    await expect(pending).rejects.toThrow("closed");
    await expect(connection.send("Page.reload")).rejects.toThrow("closed");
  });
});
