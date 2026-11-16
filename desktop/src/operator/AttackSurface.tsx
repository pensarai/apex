import { Button } from "@pensarai/design-system/ui/button";
import { Input } from "@pensarai/design-system/ui/input";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@pensarai/design-system/ui/tabs";
import {
  ArrowLeft,
  ArrowRightLeft,
  Box,
  Database,
  Globe,
  Layers,
  Network,
  Shield,
  ShieldAlert,
  X,
} from "lucide-react";
import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import type { LoadedTopology } from "../../../src/core/agents/offSecAgent/tools/topologyRecords";
import { LocalMarkdown } from "../view/LocalMarkdown";
import {
  type SurfaceEntry,
  type SurfaceTab,
  surfaceEntries,
  surfaceKey,
  surfaceLabel,
  surfaceText,
} from "./attack-surface-model";
import type { OperatorClient } from "./client";
import { adaptSessionTopology } from "./topology/adapter";
import {
  edgeNetworkRoutes,
  parseSelection,
  type TopologySelection,
} from "./topology/layout";

import "./attack-surface.css";

const TopologyGraph = lazy(() =>
  import("./topology/TopologyGraph").then((module) => ({
    default: module.TopologyGraph,
  })),
);

const tabs = [
  { id: "graph", label: "Graph" },
  { id: "map", label: "Inventory" },
  { id: "flows", label: "Flows" },
  { id: "controls", label: "Controls" },
  { id: "threats", label: "Threats" },
  { id: "retired", label: "Retired" },
] as const;

function EntryIcon({ entry }: { entry: SurfaceEntry }) {
  const Icon =
    entry.kind === "boundary"
      ? Layers
      : entry.kind === "flow"
        ? ArrowRightLeft
        : entry.kind === "control"
          ? Shield
          : entry.kind === "threat"
            ? ShieldAlert
            : entry.record.kind === "database" || entry.record.kind === "cache"
              ? Database
              : entry.record.exposure === "public"
                ? Globe
                : Box;
  return <Icon size={14} aria-hidden="true" />;
}

function FieldValue({
  value,
  markdown = false,
}: {
  value: unknown;
  markdown?: boolean;
}) {
  if (typeof value === "string")
    return markdown ? (
      <LocalMarkdown text={value} />
    ) : (
      <span className="surface-field-text">{value}</span>
    );
  if (Array.isArray(value) && value.every((item) => typeof item === "string"))
    return (
      <ul>
        {value.map((item, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: Record fields are ordered values without identifiers.
          <li key={index}>{item}</li>
        ))}
      </ul>
    );
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

function RecordDetails({
  entry,
  topology,
  select,
}: {
  entry: SurfaceEntry;
  topology: LoadedTopology;
  select: (tab: SurfaceTab, entry: SurfaceEntry) => void;
}) {
  const record = entry.record;
  const relatedFlows =
    entry.kind === "component" && !entry.retired
      ? topology.flows.filter(
          (flow) =>
            flow.fromId === record.id ||
            flow.toId === record.id ||
            (!flow.fromId && flow.from === record.name) ||
            (!flow.toId && flow.to === record.name),
        )
      : [];
  const relatedThreats =
    entry.kind === "component" && !entry.retired
      ? topology.threats.filter(
          (threat) =>
            threat.componentId === record.id ||
            (!threat.componentId && threat.component === record.name),
        )
      : [];
  const fields = Object.entries(record).filter(
    ([key, value]) =>
      ![
        "id",
        "name",
        "title",
        "evidence",
        "recordedAt",
        "parentId",
        "boundaryId",
        "fromId",
        "toId",
        "componentId",
        "controlIds",
        "appliesToIds",
        "usedByIds",
        "sessionId",
      ].includes(key) &&
      value !== undefined &&
      value !== "" &&
      !(Array.isArray(value) && value.length === 0),
  );
  return (
    <section className="surface-inspector" aria-label="Attack surface record">
      <div className="surface-record-kind">
        {entry.retired ? "Retired " : ""}
        {entry.kind}
      </div>
      <h2>
        <EntryIcon entry={entry} />
        <span>{surfaceLabel(entry)}</span>
      </h2>
      {entry.detached && (
        <p className="surface-notice">
          The containing boundary is missing or cyclic. This record is shown at
          the top level.
        </p>
      )}
      {entry.kind === "threat" && (
        <p className="surface-notice">
          Modeled threat scenario. This is not a verified vulnerability finding.
        </p>
      )}
      <dl className="surface-fields">
        {fields.map(([key, value]) => (
          <div key={key}>
            <dt>
              {key.replace(/([a-z])([A-Z])/g, "$1 $2").replaceAll("_", " ")}
            </dt>
            <dd>
              <FieldValue value={value} markdown={key === "businessLogic"} />
            </dd>
          </div>
        ))}
      </dl>
      {Array.isArray(record.evidence) && record.evidence.length > 0 && (
        <section className="surface-evidence">
          <h3>Evidence</h3>
          {record.evidence.map((value: unknown, index: number) => {
            const evidence =
              value && typeof value === "object"
                ? (value as Record<string, unknown>)
                : {};
            return (
              // biome-ignore lint/suspicious/noArrayIndexKey: Evidence is an ordered snapshot without identifiers.
              <div className="surface-evidence-item" key={index}>
                <span>
                  {surfaceText(evidence.source) || "Unspecified source"}
                </span>
                <p>{surfaceText(evidence.detail) || JSON.stringify(value)}</p>
                {surfaceText(evidence.ref) && (
                  <code>{surfaceText(evidence.ref)}</code>
                )}
              </div>
            );
          })}
        </section>
      )}
      {relatedFlows.length > 0 && (
        <section className="surface-related">
          <h3>Connected flows</h3>
          {relatedFlows.map((flow) => {
            const related: SurfaceEntry = {
              kind: "flow",
              record: flow,
              depth: 0,
            };
            return (
              <Button
                key={flow.id}
                size="sm"
                variant="ghost"
                onClick={() => select("flows", related)}
              >
                <ArrowRightLeft size={13} aria-hidden="true" />
                {surfaceLabel(related)}
              </Button>
            );
          })}
        </section>
      )}
      {relatedThreats.length > 0 && (
        <section className="surface-related">
          <h3>Threat scenarios</h3>
          {relatedThreats.map((threat) => (
            <Button
              key={threat.id}
              size="sm"
              variant="ghost"
              onClick={() =>
                select("threats", { kind: "threat", record: threat, depth: 0 })
              }
            >
              <ShieldAlert size={13} aria-hidden="true" />
              {surfaceText(threat.title)}
            </Button>
          ))}
        </section>
      )}
      <details className="surface-raw">
        <summary>Record data</summary>
        <pre>{JSON.stringify(record, null, 2)}</pre>
      </details>
      {surfaceText(record.recordedAt) && (
        <div className="surface-record-updated">
          Updated {surfaceText(record.recordedAt)}
        </div>
      )}
    </section>
  );
}

export function AttackSurface({
  client,
  sessionId,
  active,
  onClose,
}: {
  client: OperatorClient;
  sessionId: string;
  active: boolean;
  onClose: () => void;
}) {
  const [loaded, setLoaded] = useState<{
    sessionId: string;
    topology: LoadedTopology;
  }>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const refreshAction = useRef<() => void>(() => {});
  const [tab, setTab] = useState<SurfaceTab | "graph">("graph");
  const [query, setQuery] = useState("");
  const [selection, setSelection] = useState("");
  const [graphSelection, setGraphSelection] = useState("");
  const pending = useRef<{
    client: OperatorClient;
    sessionId: string;
    promise: Promise<LoadedTopology>;
  } | null>(null);
  const topology =
    loaded?.sessionId === sessionId ? loaded.topology : undefined;
  useEffect(() => {
    if (!active) return;
    let disposed = false;
    let busy = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refresh = async () => {
      if (disposed || busy || document.hidden) return;
      clearTimeout(timer);
      busy = true;
      setLoading(true);
      let request = pending.current;
      try {
        if (
          !request ||
          request.client !== client ||
          request.sessionId !== sessionId
        ) {
          request = {
            client,
            sessionId,
            promise: client.operatorAttackSurface({ sessionId }),
          };
          pending.current = request;
        }
        const data = await request.promise;
        if (!disposed) {
          setLoaded((previous) =>
            previous?.sessionId === sessionId &&
            JSON.stringify(previous.topology) === JSON.stringify(data)
              ? previous
              : { sessionId, topology: data },
          );
          setError("");
        }
      } catch (cause) {
        if (!disposed) setError(String(cause));
      } finally {
        if (pending.current === request) pending.current = null;
        busy = false;
        if (!disposed) {
          setLoading(false);
          if (!document.hidden) timer = setTimeout(() => void refresh(), 2000);
        }
      }
    };
    const visibility = () => {
      clearTimeout(timer);
      if (!document.hidden) void refresh();
    };
    refreshAction.current = () => void refresh();
    document.addEventListener("visibilitychange", visibility);
    void refresh();
    return () => {
      disposed = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [active, client, sessionId]);
  const entries = useMemo(
    () =>
      topology ? surfaceEntries(topology, tab === "graph" ? "map" : tab) : [],
    [topology, tab],
  );
  const matches = useMemo(() => {
    const term = query.trim().toLowerCase();
    return term
      ? entries.filter((entry) =>
          JSON.stringify(entry.record).toLowerCase().includes(term),
        )
      : entries;
  }, [entries, query]);
  const selected =
    matches.find((entry) => surfaceKey(entry) === selection) ?? matches[0];
  const counts = topology
    ? {
        map: topology.boundaries.length + topology.components.length,
        flows: topology.flows.length,
        controls: topology.controls.length,
        threats: topology.threats.length,
        retired: topology.retired.length,
      }
    : undefined;
  const graph = useMemo(
    () => (topology ? adaptSessionTopology(topology) : undefined),
    [topology],
  );
  const routes = useMemo(
    () => (graph ? edgeNetworkRoutes(graph.topology) : new Map()),
    [graph],
  );
  const graphSelected = useMemo(
    () =>
      graph ? parseSelection(graphSelection, graph.topology, routes) : null,
    [graphSelection, graph, routes],
  );
  const graphEntry = graphSelected && graph?.entries.get(graphSelected.id);
  const selectGraph = (next: TopologySelection) =>
    setGraphSelection(next ? `${next.type}:${next.id}` : "");
  const selectRecord = (nextTab: SurfaceTab, entry: SurfaceEntry) => {
    setQuery("");
    setTab(nextTab);
    setSelection(surfaceKey(entry));
  };
  const empty = counts && Object.values(counts).every((count) => count === 0);
  return (
    <aside
      className="attack-surface-sidebar"
      aria-label="Attack surface"
      onKeyDown={(event) => {
        if (event.key === "Escape" && !event.defaultPrevented) {
          event.stopPropagation();
          onClose();
        }
      }}
    >
      <header className="surface-header">
        <div>
          <h2>Attack surface</h2>
          <p>
            Boundaries, components and attack paths documented in this session.
          </p>
        </div>
        <Button
          size="icon-sm"
          variant="ghost"
          aria-label="Close attack surface"
          onClick={onClose}
        >
          <X size={16} aria-hidden="true" />
        </Button>
      </header>
      <div className="surface-toolbar">
        <Input
          aria-label="Search attack surface"
          placeholder="Search names, endpoints or evidence"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            if (tab === "graph" && event.target.value) setTab("map");
          }}
        />
        <span className="surface-refresh-status">
          {!topology && loading ? "Loading…" : "Updates automatically"}
        </span>
        <Button
          size="sm"
          variant="ghost"
          disabled={loading}
          onClick={() => refreshAction.current()}
        >
          Refresh
        </Button>
      </div>
      {error && (
        <div className="surface-error" role="alert">
          <span>
            {error}
            {topology && " Showing the last loaded records."}
          </span>
          <Button size="sm" onClick={() => refreshAction.current()}>
            Retry
          </Button>
        </div>
      )}
      <Tabs
        value={tab}
        onValueChange={(value) => {
          setTab(value as SurfaceTab | "graph");
          setQuery("");
          setSelection("");
        }}
        className="surface-tabs"
      >
        <TabsList variant="line" aria-label="Attack surface views">
          {tabs.map((item) => (
            <TabsTrigger key={item.id} value={item.id}>
              {item.label}{" "}
              <span className="surface-tab-count">
                {counts?.[item.id === "graph" ? "map" : item.id] ?? "—"}
              </span>
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value={tab} className="surface-tab-content">
          {empty ? (
            <div className="surface-empty">
              <Network size={28} aria-hidden="true" />
              <h2>No attack surface documented yet</h2>
              <p>
                Ask the operator to map a target or repository. Documented
                boundaries, components, flows, controls and threats will appear
                here as recon progresses.
              </p>
            </div>
          ) : !topology ? (
            <div className="surface-empty">
              <p>
                {error
                  ? "Could not load this session’s attack surface."
                  : "Loading the session’s attack surface…"}
              </p>
            </div>
          ) : tab === "graph" &&
            !topology.boundaries.length &&
            !topology.components.length ? (
            <div className="surface-empty">
              <Network size={28} aria-hidden="true" />
              <h2>No active boundaries or components</h2>
              <p>
                The graph will appear as recon documents the system. Other
                recorded and retired entries are available in their tabs.
              </p>
            </div>
          ) : tab === "graph" && graph ? (
            <div className="surface-graph-view">
              {graph.warnings.length > 0 && (
                <details className="surface-graph-warnings">
                  <summary>{graph.warnings.length} graph notices</summary>
                  <ul>
                    {graph.warnings.map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                </details>
              )}
              <div
                className={`surface-graph-layout${graphSelected ? " has-selection" : ""}`}
              >
                <Suspense
                  fallback={<div className="surface-empty">Loading graph…</div>}
                >
                  <TopologyGraph
                    topology={graph.topology}
                    selection={graphSelected}
                    onSelect={selectGraph}
                  />
                </Suspense>
                {graphSelected && (
                  <aside className="surface-graph-details">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => selectGraph(null)}
                    >
                      <ArrowLeft size={13} /> Back to overview
                    </Button>
                    {graphEntry ? (
                      <RecordDetails
                        key={surfaceKey(graphEntry)}
                        entry={graphEntry}
                        topology={topology}
                        select={selectRecord}
                      />
                    ) : graphSelected.type === "route" ? (
                      <section className="surface-inspector surface-related">
                        <h2>Edge connections</h2>
                        <p>Flows between these boundaries.</p>
                        {graphSelected.route.flows.map((flow) => {
                          const entry = flow.id
                            ? graph.entries.get(flow.id)
                            : undefined;
                          return entry ? (
                            <Button
                              key={flow.id}
                              size="sm"
                              variant="ghost"
                              onClick={() => selectRecord("flows", entry)}
                            >
                              {surfaceLabel(entry)}
                            </Button>
                          ) : null;
                        })}
                      </section>
                    ) : (
                      <p className="surface-no-matches">
                        Components with missing boundaries are grouped here.
                        Open Inventory to inspect their original records.
                      </p>
                    )}
                  </aside>
                )}
              </div>
            </div>
          ) : (
            <div className="surface-layout">
              <div
                className="surface-inventory"
                aria-label={`${tabs.find((item) => item.id === tab)?.label} records`}
              >
                {tab === "map" && (
                  <div className="surface-inventory-summary">
                    {topology.boundaries.length} boundaries ·{" "}
                    {topology.components.length} components
                  </div>
                )}
                {matches.map((entry) => (
                  <button
                    key={surfaceKey(entry)}
                    type="button"
                    className="surface-row"
                    style={{
                      paddingLeft:
                        12 + (query ? 0 : Math.min(entry.depth, 10)) * 16,
                    }}
                    aria-pressed={
                      surfaceKey(entry) === (selected && surfaceKey(selected))
                    }
                    onClick={() => setSelection(surfaceKey(entry))}
                  >
                    <EntryIcon entry={entry} />
                    <span>
                      <strong>{surfaceLabel(entry)}</strong>
                      <small>
                        {entry.kind === "flow"
                          ? surfaceText(entry.record.label)
                          : [
                              surfaceText(entry.record.kind) || entry.kind,
                              surfaceText(entry.record.exposure),
                            ]
                              .filter(Boolean)
                              .join(" · ")}
                        {entry.detached ? " · unplaced" : ""}
                      </small>
                    </span>
                  </button>
                ))}
                {!matches.length && (
                  <p className="surface-no-matches">
                    {query
                      ? "No matching records."
                      : `No ${tab === "map" ? "boundaries or components" : tab} documented.`}
                  </p>
                )}
              </div>
              {selected ? (
                <RecordDetails
                  key={surfaceKey(selected)}
                  entry={selected}
                  topology={topology}
                  select={selectRecord}
                />
              ) : (
                <div className="surface-empty">
                  <p>
                    Select a record to inspect its evidence and relationships.
                  </p>
                </div>
              )}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </aside>
  );
}
