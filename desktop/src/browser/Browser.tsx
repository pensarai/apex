import { Button } from "@pensarai/design-system/ui/button";
import { Input } from "@pensarai/design-system/ui/input";
import {
  ArrowLeft,
  ArrowRight,
  Globe,
  LoaderCircle,
  Plus,
  RefreshCw,
  X,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import type { OperatorClient } from "../operator/client";
import type { BrowserInput, BrowserState } from "./contract";
import "./browser.css";

export function Browser({
  client,
  active,
  onClose,
  onViewport,
}: {
  client: OperatorClient;
  active: boolean;
  onClose: () => void;
  onViewport: (element: HTMLDivElement | null) => void;
}) {
  const [state, setState] = useState<BrowserState>();
  const [error, setError] = useState("");
  const [address, setAddress] = useState("");
  const [retry, setRetry] = useState(0);
  const [dialogText, setDialogText] = useState("");
  const addressFocused = useRef(false);
  const mounted = useRef(false);
  const send = useCallback(
    async (input: BrowserInput) => {
      try {
        await client.operatorBrowserInput({ input });
        if (mounted.current) setError("");
      } catch (cause) {
        if (mounted.current) setError(String(cause));
      }
    },
    [client],
  );

  useEffect(() => {
    if (!active) return;
    mounted.current = true;
    let disposed = false;
    const key = `${retry}:${crypto.randomUUID()}`;
    const unsubscribe = client.subscribeBrowser((event) => {
      if (disposed) return;
      if (event.type === "state") setState(event.state);
    });
    setError("");
    void client
      .operatorBrowserWatch({ key })
      .then((next) => {
        if (!disposed) setState(next);
      })
      .catch((cause) => {
        if (!disposed) setError(String(cause));
      });
    return () => {
      disposed = true;
      mounted.current = false;
      unsubscribe();
      void client.operatorBrowserUnwatch({ key }).catch(() => undefined);
    };
  }, [client, active, retry]);

  useEffect(() => {
    if (!addressFocused.current)
      setAddress(state?.url === "about:blank" ? "" : (state?.url ?? ""));
  }, [state?.url]);
  useEffect(() => {
    setDialogText(state?.dialog?.defaultValue ?? "");
  }, [state?.dialog]);
  const locked = state?.status !== "ready" || state.agentActive;
  return (
    <aside className="op-browser" aria-label="Session browser">
      <div className="op-browser-heading">
        <strong>
          <Globe size={14} /> Browser
        </strong>
        <span className="op-browser-ownership" aria-live="polite">
          {state?.agentActive ? (
            <>
              <LoaderCircle size={12} className="op-browser-spinner" /> Agent is
              browsing
            </>
          ) : (
            "Shared with agent"
          )}
        </span>
        <Button
          size="icon-xs"
          aria-label="Close browser sidebar"
          onClick={onClose}
        >
          <X size={14} />
        </Button>
      </div>
      <div className="op-browser-tabs" aria-label="Browser tabs">
        {state?.tabs.map((tab) => (
          <div
            className="op-browser-tab"
            data-active={tab.id === state.activeTab}
            key={tab.id}
          >
            <button
              type="button"
              disabled={locked}
              aria-pressed={tab.id === state.activeTab}
              title={tab.url}
              onClick={() => void send({ type: "select-tab", id: tab.id })}
            >
              {tab.title || "New tab"}
            </button>
            <button
              type="button"
              disabled={locked}
              aria-label={`Close ${tab.title || "tab"}`}
              onClick={() => void send({ type: "close-tab", id: tab.id })}
            >
              <X size={12} />
            </button>
          </div>
        ))}
        <Button
          size="icon-xs"
          disabled={locked}
          aria-label="New browser tab"
          onClick={() => void send({ type: "new-tab" })}
        >
          <Plus size={14} />
        </Button>
      </div>
      <form
        className="op-browser-navigation"
        onSubmit={(event) => {
          event.preventDefault();
          addressFocused.current = false;
          void send({ type: "navigate", url: address });
        }}
      >
        <Button
          type="button"
          size="icon-xs"
          disabled={locked || !state?.canGoBack}
          aria-label="Go back"
          onClick={() => void send({ type: "back" })}
        >
          <ArrowLeft size={14} />
        </Button>
        <Button
          type="button"
          size="icon-xs"
          disabled={locked || !state?.canGoForward}
          aria-label="Go forward"
          onClick={() => void send({ type: "forward" })}
        >
          <ArrowRight size={14} />
        </Button>
        <Button
          type="button"
          size="icon-xs"
          disabled={locked}
          aria-label="Reload page"
          onClick={() => void send({ type: "reload" })}
        >
          <RefreshCw size={13} />
        </Button>
        <Input
          aria-label="Browser address"
          placeholder="Enter a URL…"
          value={address}
          disabled={locked}
          onFocus={() => {
            addressFocused.current = true;
          }}
          onBlur={() => {
            addressFocused.current = false;
          }}
          onChange={(event) => setAddress(event.target.value)}
        />
      </form>
      {(error || state?.error) && (
        <div className="op-browser-error" role="alert">
          <span>{error || state?.error}</span>
          <Button size="xs" onClick={() => setRetry((value) => value + 1)}>
            Reconnect
          </Button>
        </div>
      )}
      {state?.dialog && (
        <div
          className="op-browser-dialog"
          role="alertdialog"
          aria-label="Browser page dialog"
        >
          <p>{state.dialog.message}</p>
          {state.dialog.type === "prompt" && (
            <Input
              aria-label="Page dialog response"
              value={dialogText}
              onChange={(event) => setDialogText(event.target.value)}
            />
          )}
          <div className="actions">
            <Button
              size="xs"
              onClick={() => void send({ type: "dialog", accept: false })}
            >
              Dismiss
            </Button>
            <Button
              size="xs"
              onClick={() =>
                void send({ type: "dialog", accept: true, text: dialogText })
              }
            >
              OK
            </Button>
          </div>
        </div>
      )}
      <div
        ref={onViewport}
        className="op-browser-viewport"
        aria-label="Interactive browser page"
      >
        {state?.status !== "ready" && (
          <div className="op-browser-placeholder">
            <Globe size={28} />
            <strong>
              {state?.status === "error"
                ? "Browser unavailable"
                : "Opening browser…"}
            </strong>
          </div>
        )}
      </div>
    </aside>
  );
}
