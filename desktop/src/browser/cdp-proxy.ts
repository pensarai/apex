import { randomUUID } from "node:crypto";

type TargetInfo = {
  targetId: string;
  browserContextId?: string;
  type: string;
  url?: string;
};
type Message = {
  id?: number;
  method?: string;
  sessionId?: string;
  params?: {
    [key: string]: unknown;
    targetInfo?: TargetInfo;
    targetId?: string;
    sessionId?: string;
    browserContextId?: string;
    url?: string;
  };
  result?: {
    [key: string]: unknown;
    targetInfos?: TargetInfo[];
    browserContextIds?: string[];
  };
  error?: unknown;
};

// CEF exposes every partition on one endpoint; each agent must see only its own.
export function createSessionCdpProxy(options: {
  endpoint: string;
  contextId: string;
  createTarget: (url: string) => Promise<string>;
  closeTarget: (targetId: string) => void;
}) {
  const token = randomUUID();
  let internalId = 0;
  const connections = new Set<WebSocket>();
  const rootMethods = new Set([
    "Browser.getVersion",
    "Browser.setDownloadBehavior",
    "Target.getTargets",
    "Target.getBrowserContexts",
    "Target.setAutoAttach",
    "Target.setDiscoverTargets",
    "Target.attachToTarget",
    "Target.detachFromTarget",
    "Target.getTargetInfo",
    "Target.closeTarget",
    "Target.activateTarget",
    "Target.createTarget",
    "Storage.getCookies",
    "Storage.setCookies",
    "Storage.clearCookies",
  ]);
  const server = Bun.serve<{
    upstream: WebSocket;
    pending: Map<number, string>;
    targets: Set<string>;
    sessions: Map<string, string>;
    attachedTargets: Set<string>;
    internal: Map<
      number,
      {
        resolve: () => void;
        reject: (error: Error) => void;
        timer: ReturnType<typeof setTimeout>;
      }
    >;
  }>({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request, server) {
      if (new URL(request.url).pathname !== `/${token}`)
        return new Response(null, { status: 404 });
      const upstream = new WebSocket(options.endpoint);
      const data = {
        upstream,
        pending: new Map<number, string>(),
        targets: new Set<string>(),
        sessions: new Map<string, string>(),
        attachedTargets: new Set<string>(),
        internal: new Map(),
      };
      if (server.upgrade(request, { data })) return;
      upstream.close();
      return new Response(null, { status: 400 });
    },
    websocket: {
      open(client) {
        const {
          upstream,
          targets,
          sessions,
          pending,
          internal,
          attachedTargets,
        } = client.data;
        connections.add(upstream);
        const owns = (target: TargetInfo) =>
          target.browserContextId === options.contextId ||
          targets.has(target.targetId);
        upstream.onmessage = (event) => {
          const message = JSON.parse(String(event.data)) as Message;
          const params = message.params;
          if (message.id !== undefined) {
            const own = internal.get(message.id);
            if (own) {
              clearTimeout(own.timer);
              internal.delete(message.id);
              if (message.error)
                own.reject(new Error("Could not attach the new browser tab."));
              else own.resolve();
              return;
            }
            const method = pending.get(message.id);
            if (method?.startsWith("Storage.")) delete message.sessionId;
            pending.delete(message.id);
            if (method === "Target.getTargets" && message.result) {
              message.result.targetInfos = (
                message.result.targetInfos ?? []
              ).filter(owns);
              for (const target of message.result.targetInfos)
                targets.add(target.targetId);
            }
            if (method === "Target.getBrowserContexts" && message.result)
              message.result.browserContextIds = [];
          } else if (message.method === "Target.attachedToTarget") {
            if (
              !params?.targetInfo ||
              (!owns(params.targetInfo) &&
                !(message.sessionId && sessions.has(message.sessionId)))
            )
              return;
            // CEF announces a new native page as "other" before its first commit.
            if (params.targetInfo.type === "other" && !params.targetInfo.url)
              params.targetInfo.type = "page";
            targets.add(params.targetInfo.targetId);
            attachedTargets.add(params.targetInfo.targetId);
            if (params.sessionId)
              sessions.set(params.sessionId, params.targetInfo.targetId);
          } else if (params?.targetInfo) {
            if (!owns(params.targetInfo)) return;
            targets.add(params.targetInfo.targetId);
          } else if (params?.targetId && !targets.has(params.targetId)) return;
          else if (message.sessionId && !sessions.has(message.sessionId))
            return;
          if (
            message.method === "Target.detachedFromTarget" &&
            params?.sessionId
          ) {
            if (!sessions.has(params.sessionId)) return;
            sessions.delete(params.sessionId);
          }
          if (message.method === "Target.targetDestroyed" && params?.targetId) {
            targets.delete(params.targetId);
            attachedTargets.delete(params.targetId);
            for (const [session, target] of sessions)
              if (target === params.targetId) sessions.delete(session);
          }
          client.send(JSON.stringify(message));
        };
        upstream.onclose = () => client.close();
        upstream.onerror = () => client.close();
      },
      async message(client, bytes) {
        const message = JSON.parse(String(bytes)) as Message;
        const { upstream, pending, targets, sessions } = client.data;
        const fail = (reason: string) =>
          client.send(
            JSON.stringify({
              id: message.id,
              sessionId: message.sessionId,
              error: { code: -32000, message: reason },
            }),
          );
        const originalMethod = message.method;
        const params = message.params ?? {};
        if (
          (!message.sessionId && !rootMethods.has(message.method ?? "")) ||
          (["Target.", "Browser.", "Storage."].some((prefix) =>
            message.method?.startsWith(prefix),
          ) &&
            !rootMethods.has(message.method ?? "")) ||
          (params.sessionId && !sessions.has(params.sessionId)) ||
          [
            "Browser.close",
            "Target.createBrowserContext",
            "Target.disposeBrowserContext",
          ].includes(message.method ?? "") ||
          (params.browserContextId &&
            params.browserContextId !== options.contextId) ||
          (params.targetId && !targets.has(params.targetId)) ||
          (message.sessionId && !sessions.has(message.sessionId))
        ) {
          fail("This operation is outside the shared session browser.");
          return;
        }
        if (message.method === "Target.createTarget") {
          try {
            const targetId = await options.createTarget(
              String(params.url || "about:blank"),
            );
            targets.add(targetId);
            // Native CEF views are created outside CDP and need an explicit attachment.
            if (!client.data.attachedTargets.has(targetId)) {
              await new Promise<void>((resolve, reject) => {
                const id = --internalId;
                const timer = setTimeout(() => {
                  client.data.internal.delete(id);
                  reject(new Error("New browser tab attachment timed out."));
                }, 10000);
                client.data.internal.set(id, { resolve, reject, timer });
                upstream.send(
                  JSON.stringify({
                    id,
                    method: "Target.attachToTarget",
                    params: { targetId, flatten: true },
                  }),
                );
              });
            }
            client.send(
              JSON.stringify({ id: message.id, result: { targetId } }),
            );
          } catch (error) {
            fail(String(error));
          }
          return;
        }
        if (message.method === "Target.closeTarget" && params.targetId) {
          options.closeTarget(params.targetId);
          client.send(
            JSON.stringify({ id: message.id, result: { success: true } }),
          );
          return;
        }
        if (message.method === "Browser.setDownloadBehavior") {
          client.send(JSON.stringify({ id: message.id, result: {} }));
          return;
        }
        if (message.method === "Target.setAutoAttach")
          params.waitForDebuggerOnStart = false;
        const cookieMethods: Record<string, string> = {
          "Storage.getCookies": "Network.getAllCookies",
          "Storage.setCookies": "Network.setCookies",
          "Storage.clearCookies": "Network.clearBrowserCookies",
        };
        if (cookieMethods[message.method ?? ""]) {
          message.method = cookieMethods[message.method ?? ""];
          message.sessionId = [...sessions.keys()][0];
          if (!message.sessionId) {
            fail("No browser tab is connected.");
            return;
          }
          delete params.browserContextId;
        }
        message.params = params;
        if (message.id !== undefined)
          pending.set(message.id, originalMethod ?? "");
        try {
          if (upstream.readyState === WebSocket.CONNECTING)
            await new Promise<void>((resolve, reject) => {
              const finish = (error?: Error) => {
                clearTimeout(timer);
                upstream.removeEventListener("open", opened);
                upstream.removeEventListener("error", failed);
                upstream.removeEventListener("close", failed);
                if (error) reject(error);
                else resolve();
              };
              const opened = () => finish();
              const failed = () =>
                finish(new Error("Browser connection failed"));
              const timer = setTimeout(failed, 10000);
              upstream.addEventListener("open", opened);
              upstream.addEventListener("error", failed);
              upstream.addEventListener("close", failed);
            });
          if (upstream.readyState !== WebSocket.OPEN)
            throw new Error("Browser connection closed");
          upstream.send(JSON.stringify(message));
        } catch (error) {
          if (message.id !== undefined) pending.delete(message.id);
          fail(String(error));
        }
      },
      close(client) {
        for (const pending of client.data.internal.values()) {
          clearTimeout(pending.timer);
          pending.reject(new Error("Browser connection closed."));
        }
        client.data.internal.clear();
        connections.delete(client.data.upstream);
        client.data.upstream.close();
      },
    },
  });
  return {
    endpoint: `ws://127.0.0.1:${server.port}/${token}`,
    close() {
      for (const socket of connections) socket.close();
      connections.clear();
      server.stop(true);
    },
  };
}
