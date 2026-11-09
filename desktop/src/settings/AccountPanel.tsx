import { Button } from "@pensarai/design-system/ui/button";
import { useEffect, useRef, useState } from "react";
import { api } from "../view/bridge";
import type { AccountState, SettingsRequests } from "./contract";

export function AccountPanel({ refresh }: { refresh: () => void }) {
  const [account, setAccount] = useState<AccountState>({ stage: "loading" });
  const [credit, setCredit] = useState<{
    workspace: string;
    balance: number;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const sequence = useRef(0);
  const mounted = useRef(true);
  const action = async (
    request: SettingsRequests["accountAction"]["params"],
  ) => {
    const seq = ++sequence.current;
    setError("");
    setBusy(true);
    try {
      const value = await api.accountAction(request);
      if (mounted.current && seq === sequence.current) {
        setAccount(value);
        if (request.action === "disconnect") {
          setCredit(null);
          refresh();
        }
      }
    } catch (e) {
      if (mounted.current && seq === sequence.current) setError(String(e));
    } finally {
      if (mounted.current && seq === sequence.current) setBusy(false);
    }
  };
  useEffect(() => {
    mounted.current = true;
    api
      .accountAction({ action: "inspect" })
      .then((state) => {
        if (mounted.current && sequence.current === 0) setAccount(state);
      })
      .catch((e) => {
        if (mounted.current) setError(String(e));
      });
    return () => {
      mounted.current = false;
      void api.accountAction({ action: "cancel" }).catch(console.error);
    };
  }, []);
  const pending = ["loading", "authorize", "create"].includes(account.stage);
  useEffect(() => {
    if (!pending) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      const seq = sequence.current;
      try {
        const result = await api.accountStatus();
        if (!active) return;
        if (seq === sequence.current) {
          setAccount(result);
          if (result.stage === "connected") refresh();
        }
        timer = setTimeout(poll, 750);
      } catch (e) {
        if (active) setError(String(e));
      }
    };
    timer = setTimeout(poll, 300);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [pending, refresh]);
  const connectedWorkspace =
    account.stage === "connected" ? (account.workspace ?? "") : null;
  useEffect(() => {
    if (connectedWorkspace === null) return;
    let active = true;
    setCredit(null);
    void api
      .desktopBalance()
      .then((value) => {
        if (active) setCredit(value);
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, [connectedWorkspace]);
  async function balance() {
    setBusy(true);
    setError("");
    try {
      const balance = await api.desktopBalance();
      if (mounted.current) {
        setCredit(balance);
        if (!balance) setError("Sign in to view credits.");
      }
    } catch (e) {
      if (mounted.current) setError(String(e));
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  return (
    <section className="settings-stack">
      <h3>Pensar Console</h3>
      {(account.stage === "idle" || account.stage === "error") && (
        <>
          {account.stage === "error" && <p role="alert">{account.message}</p>}
          <Button disabled={busy} onClick={() => action({ action: "login" })}>
            Sign in with device code
          </Button>
          {(account.stage === "error" || account.storedCredentials) && (
            <Button
              disabled={busy}
              onClick={() => action({ action: "disconnect" })}
            >
              Disconnect saved account
            </Button>
          )}
        </>
      )}
      {account.stage === "loading" && (
        <p role="status">Checking Console connection…</p>
      )}
      {(account.stage === "authorize" || account.stage === "create") && (
        <>
          <p>
            {account.stage === "authorize"
              ? "Complete sign-in in your browser."
              : "Create a workspace in your browser."}
          </p>
          {account.code && <code>{account.code}</code>}
          <div className="settings-value">{account.url}</div>
        </>
      )}
      {pending && (
        <Button disabled={busy} onClick={() => action({ action: "cancel" })}>
          Cancel
        </Button>
      )}
      {account.stage === "choose" && (
        <>
          <p>Select a workspace.</p>
          {account.workspaces.map((w) => (
            <Button
              key={w.id}
              disabled={busy}
              onClick={() => action({ action: "select", id: w.id })}
            >
              {w.name}
            </Button>
          ))}
        </>
      )}
      {account.stage === "connected" && (
        <>
          <p>Connected{account.workspace ? ` to ${account.workspace}` : ""}.</p>
          {account.billingReady === false && (
            <p>Your workspace needs billing setup.</p>
          )}
          <div className="actions">
            {account.canSwitch && (
              <Button
                disabled={busy}
                onClick={() => action({ action: "switch" })}
              >
                Switch workspace
              </Button>
            )}
            <Button
              disabled={busy}
              onClick={() => action({ action: "disconnect" })}
            >
              Disconnect
            </Button>
          </div>
          <h3>Credits</h3>
          {credit || account.balance != null ? (
            <p>
              {credit?.workspace ?? account.workspace} · $
              {(credit?.balance ?? account.balance ?? 0).toFixed(2)}
            </p>
          ) : null}
          <div className="actions">
            <Button disabled={busy} onClick={balance}>
              Check balance
            </Button>
            <Button
              disabled={busy}
              onClick={() => action({ action: "billing" })}
            >
              Open billing
            </Button>
          </div>
        </>
      )}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
