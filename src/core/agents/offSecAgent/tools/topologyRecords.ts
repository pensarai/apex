import { randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

/**
 * The topology record store. Each topology tool call appends one JSON file
 * under `<session>/topology/`; the latest file per record id is the record.
 *
 * Records keep a stable id across calls, renames, and runs, and reference
 * each other by id (names are kept alongside for readability), so renaming
 * a component never strands the flows and controls that point at it. A
 * retired record keeps its id and gains `status: "retired"`; it leaves the
 * active topology but stays visible to the change set.
 *
 * Records written before ids existed get an id derived from their kind and
 * name (or a flow's endpoints and label), so older sessions read the same.
 */

export type RecordKind =
  | "boundary"
  | "component"
  | "flow"
  | "control"
  | "threat";
export type TopologyRecord = Record<string, unknown> & { id: string };

const ID_PREFIX: Record<RecordKind, string> = {
  boundary: "bnd",
  component: "cmp",
  flow: "flw",
  control: "ctl",
  threat: "thr",
};
const KINDS = Object.keys(ID_PREFIX) as RecordKind[];
const COLLECTION = {
  boundary: "boundaries",
  component: "components",
  flow: "flows",
  control: "controls",
  threat: "threats",
} as const;

export function topologyDir(sessionRoot: string): string {
  return join(sessionRoot, "topology");
}

export function newRecordId(kind: RecordKind): string {
  return `${ID_PREFIX[kind]}_${randomUUID().replace(/-/g, "").slice(0, 10)}`;
}

const lower = (v: unknown) => String(v ?? "").toLowerCase();

/** Identity of a flow within a topology: its endpoints and label. */
export function flowKey(fromId: string, toId: string, label: unknown): string {
  return `${fromId}|${toId}|${lower(label)}`;
}

function legacyId(kind: RecordKind, r: Record<string, unknown>): string {
  if (kind === "flow")
    return `${kind}:${lower(r.from)}|${lower(r.to)}|${lower(r.label)}`;
  if (kind === "threat")
    return `${kind}:${lower(r.component)}|${lower(r.title)}`;
  return `${kind}:${lower(r.name)}`;
}

function sanitize(name: string): string {
  const cleaned = name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
  return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned : "unnamed";
}

/** One record file: its name, its kind, and the version it holds. */
export interface StoredTopologyRecord {
  kind: RecordKind;
  file: string;
  record: TopologyRecord;
}
type Stored = StoredTopologyRecord;

/** Parse one record file's contents; undefined for a file that is not a record. */
export function parseRecordFile(
  file: string,
  raw: Record<string, unknown>,
): StoredTopologyRecord | undefined {
  const kind = KINDS.find((k) => file.startsWith(`${k}_`));
  if (!kind || !file.endsWith(".json")) return undefined;
  const id = typeof raw.id === "string" ? raw.id : legacyId(kind, raw);
  return { kind, file, record: { ...raw, id } };
}

/** Every record file in a session, in write order. */
export function readRecordFiles(sessionRoot: string): StoredTopologyRecord[] {
  const dir = topologyDir(sessionRoot);
  if (!existsSync(dir)) return [];
  const stored: Stored[] = [];
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    const parsed = parseRecordFile(
      file,
      JSON.parse(readFileSync(join(dir, file), "utf8")) as Record<
        string,
        unknown
      >,
    );
    if (parsed) stored.push(parsed);
  }
  return sortStored(stored);
}

// Order by write time; the filename breaks ties within one millisecond.
function sortStored(stored: Stored[]): Stored[] {
  return [...stored].sort(
    (a, b) =>
      String(a.record.recordedAt ?? "").localeCompare(
        String(b.record.recordedAt ?? ""),
      ) || a.file.localeCompare(b.file),
  );
}

/** Write record files into a session, e.g. ones a host persisted elsewhere. Existing files are kept. */
export function writeRecordFiles(
  sessionRoot: string,
  stored: StoredTopologyRecord[],
): number {
  const dir = topologyDir(sessionRoot);
  mkdirSync(dir, { recursive: true });
  let written = 0;
  for (const s of stored) {
    const path = join(dir, s.file);
    if (s.file !== sanitizeFile(s.file))
      throw new Error(`writeRecordFiles: unsafe record file name ${s.file}`);
    if (existsSync(path)) continue;
    writeFileSync(path, JSON.stringify(s.record, null, 2));
    written++;
  }
  return written;
}

function sanitizeFile(file: string): string {
  return file.replace(/[^A-Za-z0-9-_.]/g, "_").replace(/^\.+/, "_");
}

export interface LoadedTopology {
  boundaries: TopologyRecord[];
  components: TopologyRecord[];
  flows: TopologyRecord[];
  controls: TopologyRecord[];
  /** Threats to components: one scenario each, attached by componentId. */
  threats: TopologyRecord[];
  /** Retired records, latest version, by kind. */
  retired: { kind: RecordKind; record: TopologyRecord }[];
}

/**
 * The topology as it stands: the latest version of every record, with
 * id references resolved to the referenced record's current name.
 */
export function loadTopology(sessionRoot: string): LoadedTopology {
  return resolveTopology(readRecordFiles(sessionRoot));
}

/** {@link loadTopology} over record files held anywhere (e.g. a database), in any order. */
export function resolveTopology(
  stored: StoredTopologyRecord[],
): LoadedTopology {
  const latest = new Map<string, Stored>();
  for (const s of sortStored(stored)) latest.set(`${s.kind}:${s.record.id}`, s);
  const all = [...latest.values()];

  const nameById = new Map<string, string>();
  for (const s of all)
    if (s.kind === "boundary" || s.kind === "component" || s.kind === "control")
      nameById.set(s.record.id, String(s.record.name));
  const name = (id: unknown, fallback: unknown) =>
    (typeof id === "string" && nameById.get(id)) || fallback;
  const names = (ids: unknown, fallback: unknown) =>
    Array.isArray(ids) ? ids.map((id) => name(id, id)) : fallback;

  const resolve = (s: Stored): TopologyRecord => {
    const r = { ...s.record };
    if (s.kind === "boundary" && r.parentId)
      r.parent = name(r.parentId, r.parent);
    if (s.kind === "component") {
      r.boundary = name(r.boundaryId, r.boundary);
      if (r.usedByIds) r.usedBy = names(r.usedByIds, r.usedBy);
    }
    if (s.kind === "flow") {
      r.from = name(r.fromId, r.from);
      r.to = name(r.toId, r.to);
    }
    if (s.kind === "control" && r.appliesToIds)
      r.appliesTo = names(r.appliesToIds, r.appliesTo);
    if (s.kind === "threat") {
      r.component = name(r.componentId, r.component);
      if (r.controlIds) r.controls = names(r.controlIds, r.controls);
    }
    return r;
  };

  const active = (kind: RecordKind) =>
    all
      .filter((s) => s.kind === kind && s.record.status !== "retired")
      .map(resolve);
  return {
    boundaries: active("boundary"),
    components: active("component"),
    flows: active("flow"),
    controls: active("control"),
    threats: active("threat"),
    retired: all
      .filter((s) => s.record.status === "retired")
      .map((s) => ({ kind: s.kind, record: resolve(s) })),
  };
}

/** Append a version of a record. `record.id` is its identity across versions. */
export function writeRecord(
  sessionRoot: string,
  sessionId: string,
  kind: RecordKind,
  key: string,
  record: TopologyRecord,
): string {
  const dir = topologyDir(sessionRoot);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filepath = join(dir, `${kind}_${sanitize(key)}_${timestamp}.json`);
  writeFileSync(
    filepath,
    JSON.stringify(
      { ...record, recordedAt: new Date().toISOString(), sessionId },
      null,
      2,
    ),
  );
  return filepath;
}

/**
 * Start a session from a baseline: copy the baseline's active records, ids
 * and provenance intact, so an update run edits the earlier map instead of
 * rebuilding it. Records the update never touches keep the baseline's
 * sessionId — that is how a change set tells "unchanged, not re-verified"
 * from "re-verified".
 */
export function seedFromBaseline(
  sessionRoot: string,
  baselineSessionRoot: string,
): number {
  const dir = topologyDir(sessionRoot);
  if (existsSync(dir) && readdirSync(dir).some((f) => f.endsWith(".json")))
    throw new Error(
      `seedFromBaseline: ${dir} already holds records; seed only a fresh session`,
    );
  mkdirSync(dir, { recursive: true });
  const latest = new Map<string, Stored>();
  for (const s of readRecordFiles(baselineSessionRoot))
    latest.set(`${s.kind}:${s.record.id}`, s);
  let seeded = 0;
  for (const s of latest.values()) {
    if (s.record.status === "retired") continue;
    writeFileSync(join(dir, s.file), JSON.stringify(s.record, null, 2));
    seeded++;
  }
  return seeded;
}

/** Fields that describe a record's provenance or the agent's bookkeeping, not the system. */
const PROVENANCE = new Set([
  "id",
  "recordedAt",
  "sessionId",
  "evidence",
  "status",
  "retiredReason",
  "distinctFrom",
]);

/**
 * Reference fields and the id field behind each. A reference counts as
 * changed only when it points at a different record, so renaming a component
 * is one change on that component, not on everything that points at it.
 */
const REFERENCE_IDS: Record<string, string> = {
  parent: "parentId",
  boundary: "boundaryId",
  usedBy: "usedByIds",
  from: "fromId",
  to: "toId",
  appliesTo: "appliesToIds",
  component: "componentId",
  controls: "controlIds",
};
const ID_FIELDS = new Set(Object.values(REFERENCE_IDS));

/** An endpoint as host:port (path kept), so "http://x:80/" and "x" are the same place. */
function normalizeEndpoint(endpoint: string): string {
  const text = endpoint.trim();
  try {
    const url = new URL(text.includes("://") ? text : `http://${text}`);
    const port =
      url.port ||
      (url.protocol === "https:"
        ? "443"
        : url.protocol === "http:"
          ? "80"
          : "");
    const path = url.pathname.replace(/\/+$/, "");
    return `${url.hostname.toLowerCase()}${port ? `:${port}` : ""}${path}`;
  } catch {
    return text.toLowerCase();
  }
}

/** Compare endpoints as a set of places, not as the strings a model happened to write. */
function comparable(field: string, value: unknown): unknown {
  if (field === "endpoints" && Array.isArray(value))
    return [...new Set(value.map((e) => normalizeEndpoint(String(e))))].sort();
  return value ?? null;
}

export interface RecordChange {
  kind: RecordKind;
  id: string;
  name: string;
}

export interface TopologyChangeSet {
  added: RecordChange[];
  changed: (RecordChange & {
    fields: Record<string, { before: unknown; after: unknown }>;
  })[];
  retired: (RecordChange & { reason: string })[];
  /** Touched by the update run with no change to what it describes. */
  reverified: RecordChange[];
  /** Carried over from the baseline and not looked at again. */
  unverified: RecordChange[];
}

const label = (kind: RecordKind, r: TopologyRecord) =>
  kind === "flow"
    ? `${r.from} → ${r.to} (${r.label})`
    : kind === "threat"
      ? `${r.component}: ${r.title}`
      : String(r.name);

/**
 * What an update run changed relative to its baseline, computed from the
 * records — never asked of the model.
 */
export function diffTopology(
  baselineSessionRoot: string,
  sessionRoot: string,
  sessionId: string,
): TopologyChangeSet {
  return diffLoadedTopology(
    loadTopology(baselineSessionRoot),
    loadTopology(sessionRoot),
    sessionId,
  );
}

/** {@link diffTopology} over topologies already loaded. */
export function diffLoadedTopology(
  before: LoadedTopology,
  after: LoadedTopology,
  sessionId: string,
): TopologyChangeSet {
  const index = (t: LoadedTopology) => {
    const m = new Map<string, { kind: RecordKind; record: TopologyRecord }>();
    for (const kind of KINDS)
      for (const record of t[COLLECTION[kind]])
        m.set(`${kind}:${record.id}`, { kind, record });
    return m;
  };
  const was = index(before);
  const is = index(after);
  const change: TopologyChangeSet = {
    added: [],
    changed: [],
    retired: [],
    reverified: [],
    unverified: [],
  };
  for (const { kind, record } of after.retired)
    if (was.has(`${kind}:${record.id}`))
      change.retired.push({
        kind,
        id: record.id,
        name: label(kind, record),
        reason: String(record.retiredReason ?? ""),
      });
  for (const [key, { kind, record }] of is) {
    const base = { kind, id: record.id, name: label(kind, record) };
    const prior = was.get(key);
    if (!prior) {
      change.added.push(base);
      continue;
    }
    const fields: Record<string, { before: unknown; after: unknown }> = {};
    for (const field of new Set([
      ...Object.keys(prior.record),
      ...Object.keys(record),
    ])) {
      if (PROVENANCE.has(field) || ID_FIELDS.has(field)) continue;
      const idField = REFERENCE_IDS[field];
      const byId =
        idField !== undefined &&
        prior.record[idField] !== undefined &&
        record[idField] !== undefined;
      const compared = byId ? (idField as string) : field;
      const a = JSON.stringify(comparable(field, prior.record[compared]));
      const b = JSON.stringify(comparable(field, record[compared]));
      if (a !== b)
        fields[field] = { before: prior.record[field], after: record[field] };
    }
    if (Object.keys(fields).length) change.changed.push({ ...base, fields });
    else if (record.sessionId === sessionId) change.reverified.push(base);
    else change.unverified.push(base);
  }
  return change;
}
