import type { BrowserView } from "electrobun/bun";
import { CdpConnection } from "./cdp";

export interface NativeTarget {
  targetId: string;
  contextId: string;
  endpoint: string;
}
export interface NativeBrowserBridge {
  resolve(
    viewId: number,
    expected: { partition: string; url: string },
  ): Promise<NativeTarget>;
  remove(viewId: number): void;
}

export function nativeBrowserBridge(options: {
  getView: (id: number) => BrowserView | undefined;
  windowId: () => number;
}): NativeBrowserBridge {
  return {
    async resolve(viewId, expected) {
      const view = options.getView(viewId);
      if (
        !view ||
        view.isRemoved ||
        view.windowId !== options.windowId() ||
        view.renderer !== "cef" ||
        !view.sandbox ||
        view.partition !== expected.partition ||
        view.url !== expected.url
      )
        throw new Error("The browser view does not belong to this session.");
      for (let attempt = 0; attempt < 50; attempt++) {
        const response = await fetch("http://127.0.0.1:9339/json/version", {
          signal: AbortSignal.timeout(1000),
        }).catch(() => undefined);
        if (response?.ok) {
          const { webSocketDebuggerUrl: endpoint } =
            (await response.json()) as { webSocketDebuggerUrl: string };
          const connection = await CdpConnection.connect(endpoint);
          let target: NativeTarget | undefined;
          try {
            const { targetInfos } = await connection.send<{
              targetInfos: {
                targetId: string;
                browserContextId?: string;
                url: string;
              }[];
            }>("Target.getTargets");
            const info = targetInfos.find((item) => item.url === expected.url);
            if (info?.browserContextId)
              target = {
                targetId: info.targetId,
                contextId: info.browserContextId,
                endpoint,
              };
          } finally {
            connection.close();
          }
          if (target) return target;
        }
        await Bun.sleep(100);
      }
      throw new Error(
        "Could not connect to the embedded browser. Restart Apex and try again.",
      );
    },
    remove(viewId) {
      options.getView(viewId)?.remove();
    },
  };
}
