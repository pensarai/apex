import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@pensarai/design-system/ui/alert-dialog";
import { Button } from "@pensarai/design-system/ui/button";
import { Input } from "@pensarai/design-system/ui/input";
import { Severity } from "@pensarai/design-system/ui/severity";
import { useEffect, useState } from "react";
import type { SessionRow } from "../shared";
import { api } from "./bridge";
import { LocalMarkdown } from "./LocalMarkdown";

const PAGE_SIZE = 40;
function SessionDetails({
  row,
  resume,
  reload,
}: {
  row: SessionRow;
  reload: () => Promise<void>;
  resume: (id: string) => void;
}) {
  const [artifacts, setArtifacts] =
    useState<Awaited<ReturnType<typeof api.artifacts>>>();
  const [error, setError] = useState("");
  useEffect(() => {
    let current = true;
    api
      .artifacts({ id: row.id })
      .then((result) => {
        if (current) setArtifacts(result);
      })
      .catch((e) => {
        if (current) setError(String(e));
      });
    return () => {
      current = false;
    };
  }, [row.id]);
  return (
    <div className="detail">
      <h2>{row.name}</h2>
      <dl>
        <dt>Session ID</dt>
        <dd>{row.id}</dd>
        <dt>Target</dt>
        <dd>{row.targets.join(", ") || "Unspecified"}</dd>
        <dt>Updated</dt>
        <dd>{new Date(row.updated).toLocaleString()}</dd>
      </dl>
      <div className="actions">
        <Button onClick={() => resume(row.id)}>Resume in operator</Button>
        <Button
          onClick={() =>
            api
              .openSessionDirectory({ id: row.id })
              .catch((e) => setError(String(e)))
          }
        >
          Open folder
        </Button>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button>Delete session</Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete this session?</AlertDialogTitle>
              <AlertDialogDescription>
                {row.name} and its saved messages, findings and reports will be
                permanently removed.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                onClick={async () => {
                  try {
                    await api.deleteSession({ id: row.id });
                    await reload();
                  } catch (e) {
                    setError(String(e));
                  }
                }}
              >
                Delete session
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
      {error && <p role="alert">{error}</p>}
      {!!artifacts?.findings.length && (
        <>
          <h3>Findings</h3>
          {artifacts.findings.map((f) => (
            <details
              key={JSON.stringify([f.title, f.endpoint])}
              className="finding"
            >
              <summary>
                <Severity level={f.severity.toLowerCase()} /> {f.title}
              </summary>
              <dl>
                <dt>Endpoint</dt>
                <dd>{f.endpoint}</dd>
              </dl>
              <p>{f.description}</p>
              {f.impact && <p>{f.impact}</p>}
              {f.evidence && <pre>{f.evidence}</pre>}
              {f.remediation && <p>{f.remediation}</p>}
            </details>
          ))}
        </>
      )}
      <h3>Pentest report</h3>
      {artifacts?.report ? (
        <LocalMarkdown text={artifacts.report} sessionId={row.id} />
      ) : (
        <p>
          {artifacts
            ? "This session has no saved report."
            : error
              ? "Report unavailable."
              : "Loading report…"}
        </p>
      )}
    </div>
  );
}

export function Sessions({
  resume,
  startOperator,
  startPentest,
}: {
  resume: (id: string) => void;
  startOperator: () => void;
  startPentest: () => void;
}) {
  const [rows, setRows] = useState<SessionRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [revision, refresh] = useState(0);
  const [query, setQuery] = useState("");
  const [id, select] = useState<string>();
  const [page, setPage] = useState(0);
  const [error, setError] = useState("");
  useEffect(() => {
    let current = true;
    setLoading(true);
    setError("");
    api
      .sessions()
      .then((data) => {
        if (current) setRows(data);
      })
      .catch((e) => {
        if (current) setError(String(e));
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, []);
  const reload = async () => {
    setLoading(true);
    setError("");
    try {
      setRows(await api.sessions());
      refresh((n) => n + 1);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };
  const matches = rows.filter((row) =>
    [row.name, row.id, ...row.targets]
      .join(" ")
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const pageCount = Math.max(1, Math.ceil(matches.length / PAGE_SIZE));
  const pageIndex = Math.min(page, pageCount - 1);
  const visible = matches.slice(
    pageIndex * PAGE_SIZE,
    (pageIndex + 1) * PAGE_SIZE,
  );
  const selected = visible.find((row) => row.id === id) ?? visible[0];
  return (
    <>
      <div className="toolbar sessions-toolbar">
        <Input
          aria-label="Filter sessions"
          placeholder="Filter by name, target or session ID"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(0);
          }}
        />
        <Button size="sm" onClick={reload} disabled={loading}>
          Refresh
        </Button>
        <Button size="sm" onClick={startPentest}>
          New pentest
        </Button>
        <Button size="sm" variant="constructive" onClick={startOperator}>
          Open operator
        </Button>
      </div>
      {error && <p role="alert">{error}</p>}
      <div className="split">
        <section className="library">
          <div className="column-title">
            Session history <span>{matches.length}</span>
          </div>
          {visible.map((row) => (
            <button
              type="button"
              key={row.id}
              className="record"
              aria-pressed={row.id === selected?.id}
              onClick={() => select(row.id)}
            >
              <strong>{row.name}</strong>
              <span>{row.targets.join(", ") || "Local session"}</span>
              <time>{new Date(row.updated).toLocaleDateString()}</time>
            </button>
          ))}
          {!matches.length && (
            <p className="empty">
              {loading
                ? "Loading sessions…"
                : query
                  ? "No sessions match this filter."
                  : "New engagements will appear here."}
            </p>
          )}
          {pageCount > 1 && (
            <div className="pages">
              <Button
                size="xs"
                disabled={pageIndex === 0}
                onClick={() => setPage(pageIndex - 1)}
              >
                Previous
              </Button>
              <span>
                {pageIndex + 1} / {pageCount}
              </span>
              <Button
                size="xs"
                disabled={pageIndex + 1 >= pageCount}
                onClick={() => setPage(pageIndex + 1)}
              >
                Next
              </Button>
            </div>
          )}
        </section>
        <section className="inspector">
          <div className="column-title">Session details</div>
          {selected ? (
            <SessionDetails
              key={`${selected.id}-${revision}`}
              reload={reload}
              row={selected}
              resume={resume}
            />
          ) : (
            <div className="empty">
              <h2>No session selected</h2>
              <p>
                Start an operator session or a pentest to see its history here.
              </p>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
