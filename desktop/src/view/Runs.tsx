import { Button } from "@pensarai/design-system/ui/button";
import { useEffect, useState } from "react";
import type { RunAction, RunDetail, RunLocation, RunRow } from "../shared";
import { api, runEvents } from "./bridge";
import { NewRun } from "./NewRun";

function RunInspector({ row, store }: { row: RunRow; store?: string }) {
  const [view, setView] = useState<RunDetail>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    const key = crypto.randomUUID();
    const update = (event: Event) => {
      const item = (
        event as CustomEvent<{ key: string; view?: RunDetail; error?: string }>
      ).detail;
      if (item.key !== key) return;
      if (item.view) setView(item.view);
      if (item.error) setError(item.error);
    };
    runEvents.addEventListener("view", update);
    void api.watchRun({ id: row.id, key, store }).catch((e) => {
      if (active) setError(String(e));
    });
    return () => {
      active = false;
      runEvents.removeEventListener("view", update);
      void api.unwatchRun({ key }).catch(console.error);
    };
  }, [row.id, store]);
  const act = async (action: RunAction) => {
    setBusy(true);
    setError("");
    try {
      await api.act({ id: row.id, action, store });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  const control = view?.control;
  const attempt = view?.attempt;
  return (
    <div className="detail">
      <h2>{row.target}</h2>
      <p>{row.prompt}</p>
      <dl>
        <dt>Run ID</dt>
        <dd>{row.id}</dd>
        <dt>Model</dt>
        <dd>{row.model}</dd>
        <dt>Status</dt>
        <dd>{view?.status ?? row.status}</dd>
        <dt>Worker</dt>
        <dd>{view?.connection ?? "Connecting…"}</dd>
        {control && (
          <>
            <dt>Requested</dt>
            <dd>{control.intent}</dd>
          </>
        )}
      </dl>
      <div className="actions">
        {control && view?.status === "running" && (
          <>
            <Button
              disabled={busy || control.intent !== "run"}
              onClick={() => act({ type: "pause", revision: control.revision })}
            >
              Pause
            </Button>
            <Button
              disabled={busy || control.intent === "stop"}
              onClick={() => act({ type: "stop", revision: control.revision })}
            >
              Stop
            </Button>
          </>
        )}
        {attempt &&
          view &&
          (view.status === "paused" ||
            (view.connection === "offline" && view.status === "running")) && (
            <Button
              disabled={busy}
              onClick={() => act({ type: "resume", attempt })}
            >
              Resume
            </Button>
          )}
      </div>
      {(error || view?.error) && <p role="alert">{error || view?.error}</p>}
      {view?.approvals.map((a) => (
        <section key={a.id}>
          <h3>Approval required · {a.tool}</h3>
          <pre>{a.input}</pre>
          <div className="actions">
            <Button
              disabled={busy}
              variant="constructive"
              onClick={() => act({ type: "approved", approvalId: a.id })}
            >
              Approve
            </Button>
            <Button
              disabled={busy}
              onClick={() => act({ type: "denied", approvalId: a.id })}
            >
              Deny
            </Button>
          </div>
        </section>
      ))}
      <h3>Transcript</h3>
      {view?.transcript.length ? (
        view.transcript.map((m) => (
          <div className="turn" key={m.id}>
            <span>{m.role}</span>
            <pre>{m.text}</pre>
          </div>
        ))
      ) : (
        <p>No messages recorded yet.</p>
      )}
    </div>
  );
}

export function Runs({
  cwd,
  location,
}: {
  cwd: string;
  location: RunLocation;
}) {
  const [rows, setRows] = useState<RunRow[]>([]);
  const [id, select] = useState(location.id);
  const { store } = location;

  const [creating, create] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    api
      .runs({ store })
      .then((items) => {
        if (active) setRows(items);
      })
      .catch((e) => {
        if (active) setError(String(e));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [store]);
  const refresh = async () => {
    setLoading(true);
    setError("");
    try {
      setRows(await api.runs({ store }));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };
  const row = id ? rows.find((item) => item.id === id) : rows[0];
  return (
    <>
      <header>
        <div>
          <h1>Recorded runs</h1>
          <p>Inspect durable runs and control their workers.</p>
        </div>
        <Button
          variant="constructive"
          disabled={creating}
          onClick={() => create(true)}
        >
          New run
        </Button>
      </header>
      {error && <p role="alert">{error}</p>}
      <div className="split">
        <section className="library">
          <div className="column-title">
            Run history{" "}
            <Button size="xs" onClick={refresh} disabled={loading}>
              Refresh
            </Button>
          </div>
          {rows.map((r) => (
            <button
              type="button"
              className="record"
              aria-pressed={!creating && r.id === row?.id}
              key={r.id}
              onClick={() => {
                select(r.id);
                create(false);
              }}
            >
              <strong>{r.target}</strong>
              <span>{r.id}</span>
              <time>{r.status}</time>
            </button>
          ))}
          {!rows.length && (
            <p className="empty">
              {loading
                ? "Loading runs…"
                : "No recorded runs in the local store."}
            </p>
          )}
        </section>
        <section className="inspector">
          <div className="column-title">
            {creating ? "Run configuration" : "Run details"}
          </div>
          {creating ? (
            <NewRun
              store={store}
              cwd={cwd}
              cancel={() => create(false)}
              done={(runId) => {
                select(runId);
                create(false);
                void refresh();
              }}
            />
          ) : row ? (
            <RunInspector key={row.id} row={row} store={store} />
          ) : (
            <div className="empty">
              <h2>{id && !loading ? "Run not found" : "No run selected"}</h2>
              <p>
                Start a run to follow its transcript and review tool approvals.
              </p>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
