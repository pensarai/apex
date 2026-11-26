import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../src/core/session";
import { isBrowserFile } from "./contract";
import { browserUrl, SessionBrowser } from "./host";

vi.mock("../../../src/core/agents/offSecAgent", () => ({
  PlaywrightMcpSession: class {
    callTool = vi.fn();
    disconnect = vi.fn(async () => undefined);
  },
}));

describe("shared session browser", () => {
  afterEach(() => vi.restoreAllMocks());
  function fixture() {
    const browser = new SessionBrowser({
      getSession: () => ({ rootPath: "/unused" }) as SessionInfo,
      emit: vi.fn(),
    });
    const endpoint = vi
      .spyOn(browser, "endpoint")
      .mockResolvedValue("ws://127.0.0.1:1");
    return { browser, endpoint };
  }
  it("accepts web addresses but rejects local files, script URLs and embedded credentials", () => {
    expect(browserUrl(" example.com/path ")).toBe("https://example.com/path");
    expect(browserUrl("http://localhost:3000")).toBe("http://localhost:3000/");
    for (const value of [
      "file:///etc/passwd",
      "javascript:alert(1)",
      "https://user:secret@example.com",
      "data:text/html,hello",
      "",
    ]) {
      expect(() => browserUrl(value)).toThrow();
    }
  });
  it("opens a resolved HTML file in the shared page and reports missing files", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-browser-file-"));
    const { browser } = fixture();
    const navigate = vi
      .spyOn(
        browser as unknown as { navigate: (url: string) => Promise<void> },
        "navigate",
      )
      .mockResolvedValue(undefined);
    (browser as unknown as { active: object }).active = { id: "test" };
    try {
      const path = join(root, "Report with spaces.html");
      await writeFile(path, "<title>Report</title>");
      await browser.input({ type: "open-file", path });
      expect(navigate).toHaveBeenCalledWith(pathToFileURL(path).href);
      await expect(
        browser.input({ type: "open-file", path: join(root, "missing.html") }),
      ).rejects.toThrow("File not found");
      await expect(
        browser.input({ type: "open-file", path: join(root, "script.sh") }),
      ).rejects.toThrow("default application");
      expect(navigate).toHaveBeenCalledOnce();
    } finally {
      await browser.close();
      await rm(root, { recursive: true, force: true });
    }
  });
  it("continues ordinary web requests when no custom headers are configured", async () => {
    const { browser } = fixture();
    const send = vi.fn(async () => ({}));
    const view = { id: "view", sessionId: "page" };
    const internals = browser as unknown as {
      views: Map<string, typeof view>;
      connection: { send: typeof send; close: () => void };
      handleEvent: (event: unknown) => Promise<void>;
    };
    internals.views.set(view.id, view);
    internals.connection = { send, close: vi.fn() };
    await internals.handleEvent({
      method: "Fetch.requestPaused",
      sessionId: "page",
      params: {
        requestId: "request",
        request: {
          url: "https://example.test",
          headers: { Accept: "text/html" },
        },
      },
    });
    expect(send).toHaveBeenCalledWith(
      "Fetch.continueRequest",
      { requestId: "request" },
      "page",
    );
    await browser.close();
  });
  it("releases paused requests when header preparation fails", async () => {
    const { browser } = fixture();
    const send = vi.fn(async () => ({}));
    const view = { id: "view", sessionId: "page" };
    const internals = browser as unknown as {
      views: Map<string, typeof view>;
      connection: { send: typeof send; close: () => void };
      handleEvent: (event: unknown) => Promise<void>;
    };
    internals.views.set(view.id, view);
    internals.connection = { send, close: vi.fn() };
    await expect(
      internals.handleEvent({
        method: "Fetch.requestPaused",
        sessionId: "page",
        params: {
          requestId: "request",
          request: {
            url: "https://example.test",
            headers: { "Invalid header": "value" },
          },
        },
      }),
    ).rejects.toThrow();
    expect(send).toHaveBeenCalledWith(
      "Fetch.failRequest",
      { requestId: "request", errorReason: "Aborted" },
      "page",
    );
    await browser.close();
  });
  it("recognizes browser documents without rerouting other file types", () => {
    for (const path of [
      "report.html",
      "report.HTM",
      "chart.svg",
      "report.pdf",
      "page.xhtml",
    ])
      expect(isBrowserFile(path)).toBe(true);
    for (const path of [
      "scope.csv",
      "findings.md",
      "script.sh",
      "report.html.exe",
    ])
      expect(isBrowserFile(path)).toBe(false);
  });
  it("serializes agent actions and prevents user input while an agent action owns the page", async () => {
    const { browser } = fixture();
    let release!: () => void;
    const first = browser.agentAction(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    await vi.waitFor(() => expect(browser.snapshot().agentActive).toBe(true));
    const secondAction = vi.fn(async () => "done");
    const second = browser.agentAction(secondAction);
    await expect(
      browser.input({ type: "navigate", url: "https://example.test" }),
    ).rejects.toThrow("agent is using");
    expect(secondAction).not.toHaveBeenCalled();
    release();
    await first;
    expect(await second).toBe("done");
    expect(browser.snapshot().agentActive).toBe(false);
    await browser.close();
  });
  it("releases ownership after failure and does not run a queued cancelled action", async () => {
    const { browser, endpoint } = fixture();
    await expect(
      browser.agentAction(async () => {
        throw new Error("Navigation failed");
      }),
    ).rejects.toThrow("Navigation failed");
    expect(browser.snapshot().agentActive).toBe(false);
    endpoint.mockClear();
    const action = vi.fn();
    await expect(
      browser.agentAction(action, AbortSignal.abort()),
    ).rejects.toThrow();
    expect(action).not.toHaveBeenCalled();
    expect(endpoint).not.toHaveBeenCalled();
    expect(await browser.agentAction(async () => "recovered")).toBe(
      "recovered",
    );
    await browser.close();
  });
  it("ignores stale panel cleanup and keeps the session alive when its current panel closes", async () => {
    const { browser } = fixture();
    await browser.watch("old");
    await browser.watch("new");
    const internals = browser as unknown as { watcher?: string };
    await browser.unwatch("old");
    expect(internals.watcher).toBe("new");
    await browser.unwatch("new");
    expect(internals.watcher).toBeUndefined();
    expect(browser.session.disconnect).not.toHaveBeenCalled();
    await browser.close();
    expect(browser.session.disconnect).toHaveBeenCalledOnce();
  });
  it("closes its control connection even if the agent connection fails to disconnect", async () => {
    const { browser } = fixture();
    const close = vi.fn(async () => undefined);
    (browser as unknown as { connection: { close: typeof close } }).connection =
      {
        close,
      };
    vi.mocked(browser.session.disconnect).mockRejectedValue(
      new Error("transport failed"),
    );
    await expect(browser.close()).rejects.toThrow("transport failed");
    expect(close).toHaveBeenCalledOnce();
    await expect(browser.agentAction(async () => undefined)).rejects.toThrow(
      "closed",
    );
  });
});
