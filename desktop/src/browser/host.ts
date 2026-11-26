import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { PlaywrightMcpSession } from "../../../src/core/agents/offSecAgent";
import {
  resolveEffectiveHeaders,
  stripBrowserManagedHeaders,
} from "../../../src/core/http/targetHeaders";
import type { SessionInfo } from "../../../src/core/session";
import { createFileRequests } from "../bun/files";
import { CdpConnection, type CdpEvent } from "./cdp";
import { createSessionCdpProxy } from "./cdp-proxy";
import {
  type BrowserEvent,
  type BrowserInput,
  type BrowserState,
  type BrowserViewDescriptor,
  isBrowserFile,
} from "./contract";
import { enableAgentCursor, installAgentCursor } from "./cursor";
import type { NativeBrowserBridge, NativeTarget } from "./native";

export function browserUrl(value: string): string {
  const text = value.trim();
  if (text === "about:blank") return text;
  const url = new URL(
    /^[a-z][\w+.-]*:\/\//i.test(text) ? text : `https://${text}`,
  );
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password
  )
    throw new Error("Enter an HTTP or HTTPS address.");
  return url.href;
}
class SharedBrowserSession extends PlaywrightMcpSession {
  constructor(private owner: SessionBrowser) {
    super({ engine: "chrome", cdpEndpoint: () => owner.endpoint() });
  }
  override callTool(
    name: string,
    args: Record<string, unknown>,
    signal?: AbortSignal,
  ) {
    return this.owner.agentAction(async () => {
      const result = await super.callTool(name, args, signal);
      if (
        name === "browser_tabs" &&
        args.action === "select" &&
        typeof args.index === "number"
      )
        this.owner.selectAgentTab(args.index);
      return result;
    }, signal);
  }
  select(index: number, signal?: AbortSignal) {
    return super.callTool("browser_tabs", { action: "select", index }, signal);
  }
}
type View = BrowserViewDescriptor & {
  viewId?: number;
  targetId?: string;
  sessionId?: string;
  title?: string;
  currentUrl?: string;
};
type TargetInfo = { targetId: string; url: string; title: string };

export class SessionBrowser {
  readonly session: SharedBrowserSession;
  // Electrobun's Bun runtime cannot run Playwright's bundled WebSocket client.
  private connection?: CdpConnection;
  private proxy?: ReturnType<typeof createSessionCdpProxy>;
  private opening?: Promise<string>;
  private closed = false;
  private closing?: Promise<void>;
  private views = new Map<string, View>();
  private pendingViews = new Map<
    string,
    {
      resolve: (target: NativeTarget) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private active?: View;
  private watcher?: string;
  private actionQueue = Promise.resolve();
  private dialogSession?: string;
  private state: BrowserState = {
    status: "idle",
    url: "about:blank",
    title: "Browser",
    tabs: [],
    canGoBack: false,
    canGoForward: false,
    agentActive: false,
  };
  constructor(
    private options: {
      getSession: () => SessionInfo;
      emit: (event: BrowserEvent) => void;
      native?: NativeBrowserBridge;
    },
  ) {
    this.session = new SharedBrowserSession(this);
  }
  snapshot() {
    return { ...this.state };
  }
  private publish() {
    if (!this.closed)
      this.options.emit({ type: "state", state: this.snapshot() });
  }
  private publishViews() {
    this.options.emit({
      type: "views",
      views: [...this.views.values()].map(({ id, url, partition }) => ({
        id,
        url,
        partition,
      })),
    });
  }
  private ensureOpen() {
    if (this.closed) throw new Error("This browser session is closed.");
  }
  private send<T = Record<string, never>>(
    method: string,
    params: Record<string, unknown> = {},
    view = this.active,
  ) {
    if (!this.connection || !view?.sessionId)
      throw new Error("The browser tab is not connected.");
    return this.connection.send<T>(method, params, view.sessionId);
  }
  private createView() {
    this.ensureOpen();
    const id = randomUUID();
    const view: View = {
      id,
      url: `about:blank#apex-browser-${id}`,
      // Electrobun 1.18 nests partitions too deeply for CEF Chrome profiles.
      // Its app-specific profile root persists cookies and site storage.
      partition: "persist:..",
    };
    this.views.set(id, view);
    const pending = new Promise<NativeTarget>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingViews.delete(id);
        this.views.delete(id);
        this.publishViews();
        reject(
          new Error(
            "The native browser view did not open. Restart Apex and try again.",
          ),
        );
      }, 15000);
      this.pendingViews.set(id, { resolve, reject, timer });
    });
    this.publishViews();
    return pending;
  }
  async attachView(id: string, viewId: number) {
    this.ensureOpen();
    const view = this.views.get(id),
      pending = this.pendingViews.get(id);
    if (!view || !pending || !this.options.native)
      throw new Error("This browser tab is no longer opening.");
    view.viewId = viewId;
    try {
      const target = await this.options.native.resolve(viewId, view);
      this.ensureOpen();
      if (this.pendingViews.get(id) !== pending)
        throw new Error("This browser tab is no longer opening.");
      view.targetId = target.targetId;
      if (this.connection) await this.connectView(view);
      clearTimeout(pending.timer);
      this.pendingViews.delete(id);
      pending.resolve(target);
    } catch (error) {
      clearTimeout(pending.timer);
      this.pendingViews.delete(id);
      pending.reject(error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }
  endpoint(): Promise<string> {
    this.ensureOpen();
    if (this.opening) return this.opening;
    if (this.proxy) return Promise.resolve(this.proxy.endpoint);
    this.state = { ...this.state, status: "starting", error: undefined };
    this.publish();
    this.opening = this.launch()
      .catch((error) => {
        this.connection?.close();
        this.connection = undefined;
        this.proxy?.close();
        this.proxy = undefined;
        this.removeViews();
        this.state = {
          ...this.state,
          status: "error",
          tabs: [],
          activeTab: undefined,
          error: String(error),
        };
        this.publish();
        throw error;
      })
      .finally(() => {
        this.opening = undefined;
      });
    return this.opening;
  }
  private async launch() {
    if (!this.options.native)
      throw new Error("The shared browser requires the desktop app.");
    const target = await this.createView();
    this.ensureOpen();
    this.connection = await CdpConnection.connect(target.endpoint, (event) => {
      void this.handleEvent(event).catch((error) => {
        if (!this.closed) {
          this.state.error = String(error);
          this.publish();
        }
      });
    });
    await this.connection.send("Target.setDiscoverTargets", { discover: true });
    for (const view of this.views.values()) await this.connectView(view);
    this.proxy = createSessionCdpProxy({
      ...target,
      ownsTarget: (targetId) =>
        [...this.views.values()].some((view) => view.targetId === targetId),
      closeTarget: (targetId) => {
        const view = [...this.views.values()].find(
          (view) => view.targetId === targetId,
        );
        if (view?.viewId !== undefined)
          this.options.native?.remove(view.viewId);
      },
      createTarget: async (url) => {
        const target = await this.createView();
        const view = [...this.views.values()].find(
          (view) => view.targetId === target.targetId,
        );
        if (url !== "about:blank" && view)
          await this.navigate(browserUrl(url), view);
        return target.targetId;
      },
    });
    this.state.status = "ready";
    await this.refresh();
    return this.proxy.endpoint;
  }
  private async connectView(view: View) {
    if (!this.connection || !view.targetId || view.sessionId) return;
    const { sessionId } = await this.connection.send<{ sessionId: string }>(
      "Target.attachToTarget",
      { targetId: view.targetId, flatten: true },
    );
    view.sessionId = sessionId;
    this.active = view;
    await this.send("Page.enable", {}, view);
    await this.send(
      "Page.addScriptToEvaluateOnNewDocument",
      { source: `(${installAgentCursor.toString()})();` },
      view,
    );
    await this.send(
      "Fetch.enable",
      { patterns: [{ urlPattern: "http*", requestStage: "Request" }] },
      view,
    );
    await this.cursor(view);
    await this.refresh();
  }
  private async cursor(view: View) {
    await this.send(
      "Runtime.evaluate",
      {
        expression: `(${installAgentCursor.toString()})();(${enableAgentCursor.toString()})(${this.state.agentActive});`,
      },
      view,
    ).catch(() => undefined);
  }
  private async handleEvent(event: CdpEvent) {
    if (this.closed) return;
    if (event.method === "Target.targetInfoChanged") {
      const info = event.params.targetInfo as TargetInfo;
      const view = [...this.views.values()].find(
        (view) => view.targetId === info.targetId,
      );
      if (view) {
        view.title = info.title;
        view.currentUrl = info.url;
        await this.refresh();
      }
      return;
    }
    if (event.method === "Target.targetDestroyed") {
      const view = [...this.views.values()].find(
        (view) => view.targetId === event.params.targetId,
      );
      if (view) {
        this.views.delete(view.id);
        if (view.viewId !== undefined) this.options.native?.remove(view.viewId);
        if (this.active === view) this.active = [...this.views.values()].at(-1);
        this.publishViews();
        await this.refresh();
      }
      return;
    }
    const view = [...this.views.values()].find(
      (view) => view.sessionId === event.sessionId,
    );
    if (!view) return;
    if (event.method === "Fetch.requestPaused") {
      const { requestId, request } = event.params as {
        requestId: string;
        request: { url: string; headers: Record<string, string> };
      };
      try {
        const custom =
          stripBrowserManagedHeaders(
            resolveEffectiveHeaders(this.options.getSession(), request.url),
          ) ?? {};
        const headers = new Headers(request.headers);
        for (const [name, value] of Object.entries(custom))
          headers.set(name, value);
        await this.send(
          "Fetch.continueRequest",
          {
            requestId,
            ...(Object.keys(custom).length
              ? {
                  headers: [...headers].map(([name, value]) => ({
                    name,
                    value,
                  })),
                }
              : {}),
          },
          view,
        );
      } catch (error) {
        // Navigation can release an interception before its continuation arrives.
        if (
          error instanceof Error &&
          /^Invalid InterceptionId\.?$/.test(error.message)
        )
          return;
        await this.send(
          "Fetch.failRequest",
          { requestId, errorReason: "Aborted" },
          view,
        ).catch(() => undefined);
        throw error;
      }
    } else if (event.method === "Page.domContentEventFired") {
      await this.cursor(view);
      const { result } = await this.send<{
        result: { value?: { title: string; url: string } };
      }>(
        "Runtime.evaluate",
        {
          expression: "({title:document.title,url:location.href})",
          returnByValue: true,
        },
        view,
      );
      if (result.value) {
        view.title = result.value.title;
        view.currentUrl = result.value.url;
      }
      await this.refresh();
    } else if (event.method === "Page.javascriptDialogOpening") {
      this.dialogSession = view.sessionId;
      this.state.dialog = event.params as unknown as NonNullable<
        BrowserState["dialog"]
      >;
      this.publish();
    } else if (event.method === "Page.javascriptDialogClosed") {
      this.dialogSession = undefined;
      this.state.dialog = undefined;
      this.publish();
    }
  }
  private async refresh() {
    this.state.tabs = [...this.views.values()]
      .filter((view) => view.sessionId)
      .map((view) => ({
        id: view.id,
        title:
          view.title && !view.title.startsWith("about:blank")
            ? view.title
            : "New tab",
        url: (view.currentUrl || view.url).startsWith(
          "about:blank#apex-browser-",
        )
          ? "about:blank"
          : view.currentUrl || view.url,
      }));
    this.state.activeTab = this.active?.id;
    const tab = this.state.tabs.find((tab) => tab.id === this.active?.id);
    this.state.url = tab?.url ?? "about:blank";
    this.state.title = tab?.title ?? "Browser";
    const active = this.active;
    if (active?.sessionId) {
      const history = await this.send<{
        currentIndex: number;
        entries: unknown[];
      }>("Page.getNavigationHistory", {}, active).catch(() => undefined);
      if (this.active !== active || this.closed) return;
      this.state.canGoBack = !!history && history.currentIndex > 0;
      this.state.canGoForward =
        !!history && history.currentIndex < history.entries.length - 1;
    } else {
      this.state.canGoBack = false;
      this.state.canGoForward = false;
    }
    this.publish();
  }
  async watch(key: string) {
    this.watcher = key;
    this.publishViews();
    await this.endpoint();
    return this.snapshot();
  }
  async unwatch(key: string) {
    if (this.watcher === key) this.watcher = undefined;
  }
  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.actionQueue
      .catch(() => undefined)
      .then(() => {
        this.ensureOpen();
        return operation();
      });
    this.actionQueue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
  selectAgentTab(index: number) {
    const view = [...this.views.values()].filter((view) => view.sessionId)[
      index
    ];
    if (view) this.active = view;
  }
  agentAction<T>(
    operation: () => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T> {
    return this.enqueue(async () => {
      signal?.throwIfAborted();
      await this.endpoint();
      signal?.throwIfAborted();
      this.state.agentActive = true;
      this.state.error = undefined;
      this.publish();
      try {
        const index = [...this.views.values()]
          .filter((view) => view.sessionId)
          .indexOf(this.active as View);
        if (index >= 0) await this.session.select(index, signal);
        await Promise.all(
          [...this.views.values()]
            .filter((view) => view.sessionId)
            .map((view) => this.cursor(view)),
        );
        return await operation();
      } finally {
        this.state.agentActive = false;
        await Promise.all(
          [...this.views.values()]
            .filter((view) => view.sessionId)
            .map((view) => this.cursor(view)),
        );
        await this.refresh();
      }
    });
  }
  private async navigate(url: string, view = this.active) {
    const result = await this.send<{ errorText?: string }>(
      "Page.navigate",
      { url },
      view,
    );
    if (result.errorText) throw new Error(result.errorText);
  }
  async input(input: BrowserInput) {
    if (input.type === "dialog") {
      if (this.dialogSession)
        await this.connection?.send(
          "Page.handleJavaScriptDialog",
          { accept: input.accept, promptText: input.text },
          this.dialogSession,
        );
      return this.snapshot();
    }
    if (this.state.agentActive)
      throw new Error(
        "The agent is using the browser. Try again when its action finishes.",
      );
    return this.enqueue(async () => {
      await this.endpoint();
      this.state.error = undefined;
      if (
        !this.active &&
        !["new-tab", "close-tab", "select-tab"].includes(input.type)
      )
        await this.createView();
      switch (input.type) {
        case "open-file": {
          if (!isBrowserFile(input.path))
            throw new Error("This file type opens in its default application.");
          const session = this.options.getSession();
          await createFileRequests({
            cwd: () => session.config?.agentCwd ?? session.rootPath,
            requireAcceptance: () => this.ensureOpen(),
            openPath: async (path) => {
              await this.navigate(pathToFileURL(path).href);
              return true;
            },
          }).openLocalFile({
            path: input.path,
            sessionId: input.sessionId ?? session.id,
          });
          break;
        }
        case "navigate":
          await this.navigate(browserUrl(input.url));
          break;
        case "back":
        case "forward": {
          const history = await this.send<{
            currentIndex: number;
            entries: { id: number }[];
          }>("Page.getNavigationHistory");
          const entry =
            history.entries[
              history.currentIndex + (input.type === "back" ? -1 : 1)
            ];
          if (entry)
            await this.send("Page.navigateToHistoryEntry", {
              entryId: entry.id,
            });
          break;
        }
        case "reload":
          await this.send("Page.reload");
          break;
        case "new-tab":
          await this.createView();
          if (input.url) await this.navigate(browserUrl(input.url));
          break;
        case "select-tab": {
          const view = this.views.get(input.id);
          if (!view?.sessionId) throw new Error("This browser tab is closed.");
          this.active = view;
          break;
        }
        case "close-tab": {
          const view = this.views.get(input.id);
          if (view?.viewId !== undefined)
            this.options.native?.remove(view.viewId);
          break;
        }
      }
      await this.refresh();
      return this.snapshot();
    });
  }
  private removeViews() {
    for (const view of this.views.values())
      if (view.viewId !== undefined) this.options.native?.remove(view.viewId);
    this.views.clear();
    this.active = undefined;
    this.publishViews();
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    for (const pending of this.pendingViews.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("This browser session is closed."));
    }
    this.pendingViews.clear();
    this.closing = (async () => {
      try {
        await this.session.disconnect();
        await this.opening?.catch(() => undefined);
      } finally {
        this.connection?.close();
        this.proxy?.close();
        this.removeViews();
      }
    })();
    return this.closing;
  }
}
