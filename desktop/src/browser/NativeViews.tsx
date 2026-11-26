import type { WebviewTagElement } from "electrobun/view";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { OperatorClient } from "../operator/client";
import type { BrowserState, BrowserViewDescriptor } from "./contract";

export function NativeViews({
  client,
  visible,
  viewport,
}: {
  client: OperatorClient;
  visible: boolean;
  viewport: HTMLDivElement | null;
}) {
  const [views, setViews] = useState<BrowserViewDescriptor[]>([]);
  const [state, setState] = useState<BrowserState>();
  useEffect(
    () =>
      client.subscribeBrowser((event) => {
        if (event.type === "views") setViews(event.views);
        else setState(event.state);
      }),
    [client],
  );
  return (
    <>
      {views.map((view) => (
        <NativeView
          key={view.id}
          view={view}
          client={client}
          visible={visible && state?.activeTab === view.id}
          busy={!!state?.agentActive}
          viewport={viewport}
        />
      ))}
    </>
  );
}

function NativeView({
  view,
  client,
  visible,
  busy,
  viewport,
}: {
  view: BrowserViewDescriptor;
  client: OperatorClient;
  visible: boolean;
  busy: boolean;
  viewport: HTMLDivElement | null;
}) {
  const mount = useRef<HTMLDivElement>(null);
  const element = useRef<WebviewTagElement | undefined>(undefined);
  useLayoutEffect(() => {
    const parent = mount.current;
    if (!parent) return;
    const node = document.createElement("electrobun-webview");
    element.current = node;
    node.setAttribute("renderer", "cef");
    node.setAttribute("sandbox", "");
    node.setAttribute("partition", view.partition);
    node.setAttribute("src", view.url);
    node.setAttribute(
      "masks",
      '[role="dialog"], [data-radix-popper-content-wrapper]',
    );
    node.style.cssText =
      "position:fixed;left:-10000px;top:0;width:1000px;height:720px;visibility:hidden;";
    parent.append(node);
    let disposed = false;
    const ready = setInterval(() => {
      if (node.webviewId === undefined || node.webviewId === null) return;
      clearInterval(ready);
      node.toggleHidden(true);
      void client
        .operatorBrowserAttach({ id: view.id, viewId: node.webviewId })
        .catch((error) => {
          if (!disposed) console.error("Could not attach browser view:", error);
        });
    }, 20);
    const popup = (event: CustomEvent) => {
      let detail = event.detail;
      if (typeof detail === "string" && detail.startsWith("{")) {
        try {
          detail = JSON.parse(detail);
        } catch {
          return;
        }
      }
      const url = typeof detail === "string" ? detail : detail?.url;
      if (typeof url === "string" && /^https?:\/\//i.test(url))
        void client
          .operatorBrowserInput({ input: { type: "new-tab", url } })
          .catch(console.error);
    };
    node.on("new-window-open", popup);
    return () => {
      disposed = true;
      clearInterval(ready);
      node.off("new-window-open", popup);
      node.remove();
      element.current = undefined;
    };
  }, [client, view.id, view.url, view.partition]);
  useLayoutEffect(() => {
    const node = element.current;
    if (!node) return;
    const sync = () => {
      const showing = visible && !!viewport;
      // Electrobun hides the native view but leaves the tag's white background.
      node.style.visibility = showing ? "visible" : "hidden";
      node.toggleHidden(!showing);
      node.togglePassthrough(busy || !showing);
      if (showing) {
        const box = viewport.getBoundingClientRect();
        Object.assign(node.style, {
          left: `${box.left}px`,
          top: `${box.top}px`,
          width: `${box.width}px`,
          height: `${box.height}px`,
        });
        node.syncDimensions(true);
      }
    };
    const observer = new ResizeObserver(sync);
    if (viewport) observer.observe(viewport);
    window.addEventListener("resize", sync);
    sync();
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", sync);
    };
  }, [visible, busy, viewport]);
  return <div ref={mount} />;
}
