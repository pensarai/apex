import {
  Background,
  BackgroundVariant,
  BaseEdge,
  Controls,
  type Edge,
  type EdgeProps,
  getNodesBounds,
  Handle,
  MarkerType,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  useReactFlow,
  useStore,
} from "@xyflow/react";
import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import "@xyflow/react/dist/style.css";
import { Button } from "@pensarai/design-system/ui/button";
import { controlsOn, INTERNET, publicEntrypoints } from "./graph";
import {
  absoluteBox,
  activeSet,
  COMPONENT_H,
  COMPONENT_W,
  componentsWithin,
  EXPECTS_CONTROLS,
  edgeNetworkRoutes,
  facingHandles,
  focusedFlows,
  layoutTopology,
  type Positioned,
  strongest,
  structureKey,
  type TopologySelection,
} from "./layout";
import type { Boundary, Component, Evidence, Topology } from "./types";
import "./topology-graph.css";

const EDGE_DASH: Record<ReturnType<typeof strongest>, string | undefined> = {
  observed: undefined,
  cloud: "6 2 1 2",
  source: "5 4",
  inferred: "1 4",
};

function cn(...values: (string | false | undefined)[]) {
  return values.filter(Boolean).join(" ");
}

interface ComponentData extends Record<string, unknown> {
  component?: Component;
  controlCount: number;
  threatCount: number;
  dimmed: boolean;
  selected: boolean;
}

function ConnectionHandles() {
  return Object.values(Position).map((side) => (
    <Fragment key={side}>
      <Handle
        id={`out-${side}`}
        type="source"
        position={side}
        className="invisible"
      />
      <Handle
        id={`in-${side}`}
        type="target"
        position={side}
        className="invisible"
      />
    </Fragment>
  ));
}

function ComponentNode({ data }: NodeProps<Node<ComponentData>>) {
  const { component, controlCount, threatCount, dimmed, selected } = data;
  if (!component)
    return (
      <button
        type="button"
        aria-pressed={selected}
        className={cn(
          "flex h-[62px] w-[120px] flex-col justify-center border border-info/50 bg-surface-2 px-2 transition-opacity",
          dimmed && "opacity-25",
        )}
      >
        <ConnectionHandles />
        <strong className="text-xs text-fg">Internet</strong>
        <span className="text-xs text-fg-3">attackers, users</span>
      </button>
    );
  const evidence = strongest(component.evidence);
  return (
    <button
      type="button"
      aria-pressed={selected}
      style={{ width: COMPONENT_W, height: COMPONENT_H }}
      className={cn(
        "flex cursor-pointer flex-col justify-center gap-0.5 border bg-surface px-2 transition-opacity",
        evidence === "observed"
          ? "border-border-strong"
          : "border-dashed border-border-strong",
        component.exposure === "public" && "border-l-2 border-l-info",
        selected && "border-fg",
        dimmed && "opacity-25",
      )}
    >
      <ConnectionHandles />
      <span className="flex items-center gap-1.5 text-xs text-fg-3">
        {component.kind.replace("-", " ")}
        {component.exposure === "public" && (
          <span className="uppercase text-info">public</span>
        )}
        {controlCount > 0 ? (
          <span>{controlCount} ctl</span>
        ) : (
          EXPECTS_CONTROLS.has(component.kind) && (
            <span className="text-warning">no controls</span>
          )
        )}
        {threatCount > 0 && (
          <span className="text-error">{threatCount} thr</span>
        )}
      </span>
      <strong className="truncate text-xs text-fg">{component.name}</strong>
      <span className="truncate text-xs text-fg-3">{component.tech}</span>
    </button>
  );
}

interface BoundaryData extends Record<string, unknown> {
  boundary: Boundary;
  controlCount: number;
  dimmed: boolean;
  selected: boolean;
}

const OUTSIDE_BOUNDARY = new Set([
  "third-party",
  "user-device",
  "edge-network",
  "unplaced",
]);

function BoundaryNode({ data }: NodeProps<Node<BoundaryData>>) {
  const { boundary, controlCount, dimmed, selected } = data;
  return (
    <button
      type="button"
      aria-pressed={selected}
      className={cn(
        "h-full w-full cursor-pointer border bg-canvas/40 transition-opacity",
        OUTSIDE_BOUNDARY.has(boundary.kind)
          ? "border-dashed border-border"
          : "border-border-strong",
        boundary.kind === "unplaced" && "border-warning/50",
        selected && "border-fg",
        dimmed && "opacity-40",
      )}
    >
      <Handle type="target" position={Position.Left} className="invisible" />
      <Handle type="source" position={Position.Right} className="invisible" />
      <span className="flex items-baseline gap-2 px-2 py-1.5">
        <strong className="text-xs text-fg">{boundary.name}</strong>
        <span className="text-xs text-fg-3">
          {boundary.kind.replace("-", " ")}
          {controlCount > 0 &&
            ` · ${controlCount} control${controlCount === 1 ? "" : "s"}`}
        </span>
      </span>
    </button>
  );
}

const NODE_TYPES = { component: ComponentNode, boundary: BoundaryNode };

type OverviewEdge = Edge<{ path: string }, "overview">;
function OverviewRoute({
  id,
  data,
  style,
  markerEnd,
}: EdgeProps<OverviewEdge>) {
  return (
    <BaseEdge
      id={id}
      path={data?.path ?? ""}
      style={style}
      markerEnd={markerEnd}
    />
  );
}
const EDGE_TYPES = { overview: OverviewRoute };

function FitSelection({
  active,
  positions,
}: {
  active: Set<string> | null;
  positions: Map<string, Positioned>;
}) {
  const { fitBounds, viewportInitialized } = useReactFlow();
  const width = useStore((s) => s.width);
  const height = useStore((s) => s.height);
  const activeKey = active ? JSON.stringify([...active].sort()) : null;
  useEffect(() => {
    const activeIds = activeKey ? (JSON.parse(activeKey) as string[]) : null;
    if (!viewportInitialized || !width || !height) return;
    const boxes = [...(activeIds ?? positions.keys())]
      .filter((id) => positions.has(id))
      .map((id) => {
        const { x, y, width, height } = absoluteBox(positions, id);
        return { id, data: {}, position: { x, y }, width, height };
      });
    if (boxes.length) void fitBounds(getNodesBounds(boxes), { padding: 0.15 });
  }, [fitBounds, viewportInitialized, width, height, activeKey, positions]);
  return null;
}

export function TopologyGraph({
  topology,
  selection: requestedSelection,
  onSelect: select,
}: {
  topology: Topology;
  selection: TopologySelection;
  onSelect: (selection: TopologySelection) => void;
}) {
  const [colorMode, setColorMode] = useState<"light" | "dark">(() =>
    document.documentElement.dataset.theme === "light" ? "light" : "dark",
  );
  useEffect(() => {
    const root = document.documentElement;
    const observer = new MutationObserver(() => {
      setColorMode(root.dataset.theme === "light" ? "light" : "dark");
    });
    observer.observe(root, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    return () => observer.disconnect();
  }, []);
  const [layout, setLayout] = useState<Awaited<
    ReturnType<typeof layoutTopology>
  > | null>(null);
  const [layoutError, setLayoutError] = useState<string | null>(null);
  const [layoutAttempt, setLayoutAttempt] = useState(0);
  const positions = layout?.positions;
  const routes = useMemo(() => edgeNetworkRoutes(topology), [topology]);
  const selection = useMemo(() => {
    if (requestedSelection?.type !== "route") return requestedSelection;
    const route = routes.get(requestedSelection.id);
    return route ? { type: "route" as const, id: route.id, route } : null;
  }, [requestedSelection, routes]);
  const currentGraph = useRef({ topology, routes });
  currentGraph.current = { topology, routes };

  const structure = structureKey(topology);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Only structural changes or an explicit retry should rerun layout.
  useEffect(() => {
    let cancelled = false;
    setLayoutError(null);
    setLayout(null);
    const { topology, routes } = currentGraph.current;
    void layoutTopology(topology, routes).then(
      (result) => {
        if (!cancelled) setLayout(result);
      },
      (error: unknown) => {
        if (cancelled) return;
        setLayout(null);
        setLayoutError(error instanceof Error ? error.message : String(error));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [structure, layoutAttempt]);

  const active = useMemo(
    () => activeSet(topology, selection),
    [topology, selection],
  );
  const threatsOf = useMemo(() => {
    const counts = new Map<string, number>();
    for (const t of topology.threats)
      counts.set(t.component, (counts.get(t.component) ?? 0) + 1);
    return counts;
  }, [topology]);

  const selectNode = useCallback(
    (id: string, type: string | undefined) => {
      select(
        id === INTERNET
          ? null
          : { type: type === "boundary" ? "boundary" : "component", id },
      );
    },
    [select],
  );
  const nodes = useMemo<Node[]>(() => {
    if (!positions) return [];
    const ordered: Node[] = [];
    const place = (id: string) => {
      const p = positions.get(id) ?? {
        x: 0,
        y: 0,
        width: COMPONENT_W,
        height: COMPONENT_H,
      };
      return {
        position: { x: p.x, y: p.y },
        ...(p.parent ? { parentId: p.parent } : {}),
      };
    };
    const visit = (parent: string | undefined) => {
      for (const b of topology.boundaries.filter((b) => b.parent === parent)) {
        const p = positions.get(b.id);
        const inside = componentsWithin(topology, b.id);
        ordered.push({
          id: b.id,
          type: "boundary",
          ariaLabel: `Boundary: ${b.name}`,
          ...place(b.id),
          style: {
            width: p?.width ?? COMPONENT_W,
            height: p?.height ?? COMPONENT_H,
          },
          data: {
            boundary: b,
            controlCount: controlsOn(topology, b.id).length,
            dimmed:
              Boolean(active) && ![...inside].some((id) => active?.has(id)),
            selected: selection?.id === b.id,
          } satisfies BoundaryData,
        });
        visit(b.id);
      }
      for (const c of topology.components.filter((c) => c.boundary === parent))
        ordered.push({
          id: c.id,
          type: "component",
          ariaLabel: `Component: ${c.name}`,
          ...place(c.id),
          data: {
            component: c,
            controlCount: controlsOn(topology, c.id).length,
            threatCount: threatsOf.get(c.id) ?? 0,
            dimmed: Boolean(active) && !active?.has(c.id),
            selected: selection?.id === c.id,
          } satisfies ComponentData,
        });
    };
    ordered.push({
      id: INTERNET,
      type: "component",
      ariaLabel: "Internet: return to overview",
      ...place(INTERNET),
      data: {
        controlCount: 0,
        threatCount: 0,
        dimmed: Boolean(active) && !active?.has(INTERNET),
        selected: false,
      } satisfies ComponentData,
    });
    visit(undefined);
    return ordered;
  }, [positions, topology, active, selection, threatsOf]);

  const edges = useMemo<Edge[]>(() => {
    if (!layout) return [];
    if (!selection || !active)
      return layout.overview.map(({ path, ...edge }) => {
        const route = routes.get(edge.id);
        return {
          ...edge,
          type: path ? "overview" : "smoothstep",
          data: { path },
          style: {
            stroke: route ? "var(--color-fg-2)" : "var(--color-info)",
            strokeWidth: route ? 2 : 1,
          },
          ...(route && {
            ariaRole: "button",
            focusable: true,
            className: "cursor-pointer",
            domAttributes: {
              onKeyDown: (event: React.KeyboardEvent<SVGGElement>) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  select({ type: "route", id: route.id, route });
                }
              },
            },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: "var(--color-fg-2)",
            },
            ariaLabel: `Show edge connections from ${route.source} to ${route.target}`,
          }),
        };
      });
    const inside =
      selection.type === "boundary"
        ? componentsWithin(topology, selection.id)
        : active;
    const entries = publicEntrypoints(topology).filter((c) =>
      selection.type === "component"
        ? c.id === selection.id
        : selection.type !== "route" && inside.has(c.id),
    );
    const byPair = new Map<
      string,
      { source: string; target: string; evidence: Evidence[] }
    >();
    for (const f of focusedFlows(topology, selection, active)) {
      const id = JSON.stringify([f.from, f.to]);
      const pair = byPair.get(id);
      if (pair) pair.evidence.push(...f.evidence);
      else
        byPair.set(id, {
          source: f.from,
          target: f.to,
          evidence: [...f.evidence],
        });
    }
    return [
      ...entries.map((c) => ({
        id: `${INTERNET}->${c.id}`,
        source: INTERNET,
        target: c.id,
        ...facingHandles(layout.positions, INTERNET, c.id),
        style: { stroke: "var(--color-info)" },
      })),
      ...[...byPair].map(([id, { source, target, evidence }]) => ({
        id,
        source,
        target,
        ...facingHandles(layout.positions, source, target),
        markerEnd: { type: MarkerType.ArrowClosed, color: "var(--color-fg-2)" },
        zIndex: 10,
        style: {
          stroke: "var(--color-fg-2)",
          strokeWidth: 1.5,
          strokeDasharray: EDGE_DASH[strongest(evidence)],
        },
      })),
    ];
  }, [topology, active, selection, layout, routes, select]);

  return (
    <div className="session-topology-graph">
      <div className="session-topology-canvas">
        {!selection && (
          <p className="border-b border-border px-3 py-1.5 text-xs text-fg-3">
            Blue lines show Internet access. Select an edge-network arrow to see
            the components it connects.
          </p>
        )}
        {positions ? (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={NODE_TYPES}
            edgeTypes={EDGE_TYPES}
            colorMode={colorMode}
            minZoom={0.1}
            maxZoom={2.5}
            nodesFocusable={false}
            nodesDraggable={false}
            nodesConnectable={false}
            elevateNodesOnSelect={false}
            onEdgeClick={(_, edge) => {
              const route = routes.get(edge.id);
              if (route && !selection)
                select({ type: "route", id: route.id, route });
            }}
            onNodeClick={(_, node) => selectNode(node.id, node.type)}
            onPaneClick={() => select(null)}
            proOptions={{ hideAttribution: true }}
          >
            <FitSelection active={active} positions={positions} />
            <Background
              variant={BackgroundVariant.Dots}
              gap={24}
              size={1}
              color="var(--color-border)"
            />
            <Controls showInteractive={false} position="bottom-left" />
          </ReactFlow>
        ) : layoutError !== null ? (
          <div className="flex flex-col items-center gap-3 px-4 py-16">
            <p role="alert" className="text-sm text-error">
              The map layout failed. {layoutError}
            </p>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setLayoutAttempt((attempt) => attempt + 1)}
            >
              Retry layout
            </Button>
          </div>
        ) : (
          <p className="px-4 py-16 text-center font-mono text-xs text-fg-3">
            Laying out…
          </p>
        )}
        {selection && (
          <div className="session-topology-evidence">
            <span>— seen live</span>
            <span>- - from source</span>
            <span>-·- cloud API</span>
            <span>··· inferred</span>
          </div>
        )}
      </div>
    </div>
  );
}
