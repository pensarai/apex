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

export type RecordKind = "boundary" | "component" | "flow" | "control";
export type TopologyRecord = Record<string, unknown> & { id: string };

const ID_PREFIX: Record<RecordKind, string> = {
  boundary: "bnd",
  component: "cmp",
  flow: "flw",
  control: "ctl",
};
const KINDS = Object.keys(ID_PREFIX) as RecordKind[];
const COLLECTION = {
  boundary: "boundaries",
  component: "components",
  flow: "flows",
  control: "controls",
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
  return kind === "flow"
    ? `${kind}:${lower(r.from)}|${lower(r.to)}|${lower(r.label)}`
    : `${kind}:${lower(r.name)}`;
}

function sanitize(name: string): string {
  const cleaned = name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
  return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned : "unnamed";
}

interface Stored {
  kind: RecordKind;
  file: string;
  record: TopologyRecord;
}

function readStored(sessionRoot: string): Stored[] {
  const dir = topologyDir(sessionRoot);
  if (!existsSync(dir)) return [];
  const stored: Stored[] = [];
  for (const file of readdirSync(dir)) {
    const kind = KINDS.find((k) => file.startsWith(`${k}_`));
    if (!kind || !file.endsWith(".json")) continue;
    const raw = JSON.parse(readFileSync(join(dir, file), "utf8")) as Record<
      string,
      unknown
    >;
    const id = typeof raw.id === "string" ? raw.id : legacyId(kind, raw);
    stored.push({ kind, file, record: { ...raw, id } });
  }
  // Order by write time; the filename breaks ties within one millisecond.
  return stored.sort(
    (a, b) =>
      String(a.record.recordedAt ?? "").localeCompare(
        String(b.record.recordedAt ?? ""),
      ) || a.file.localeCompare(b.file),
  );
}

export interface LoadedTopology {
  boundaries: TopologyRecord[];
  components: TopologyRecord[];
  flows: TopologyRecord[];
  controls: TopologyRecord[];
  /** Retired records, latest version, by kind. */
  retired: { kind: RecordKind; record: TopologyRecord }[];
}

/**
 * The topology as it stands: the latest version of every record, with
 * id references resolved to the referenced record's current name.
 */
export function loadTopology(sessionRoot: string): LoadedTopology {
  const latest = new Map<string, Stored>();
  for (const s of readStored(sessionRoot))
    latest.set(`${s.kind}:${s.record.id}`, s);
  const all = [...latest.values()];

  const nameById = new Map<string, string>();
  for (const s of all)
    if (s.kind === "boundary" || s.kind === "component")
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
  for (const s of readStored(baselineSessionRoot))
    latest.set(`${s.kind}:${s.record.id}`, s);
  let seeded = 0;
  for (const s of latest.values()) {
    if (s.record.status === "retired") continue;
    writeFileSync(join(dir, s.file), JSON.stringify(s.record, null, 2));
    seeded++;
  }
  return seeded;
}

/** Fields that describe a record's provenance, not the system. */
const PROVENANCE = new Set([
  "id",
  "recordedAt",
  "sessionId",
  "evidence",
  "status",
  "retiredReason",
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
};
const ID_FIELDS = new Set(Object.values(REFERENCE_IDS));

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
  kind === "flow" ? `${r.from} → ${r.to} (${r.label})` : String(r.name);

/**
 * What an update run changed relative to its baseline, computed from the
 * records — never asked of the model.
 */
export function diffTopology(
  baselineSessionRoot: string,
  sessionRoot: string,
  sessionId: string,
): TopologyChangeSet {
  const before = loadTopology(baselineSessionRoot);
  const after = loadTopology(sessionRoot);
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
      const a = JSON.stringify(prior.record[compared] ?? null);
      const b = JSON.stringify(record[compared] ?? null);
      if (a !== b)
        fields[field] = { before: prior.record[field], after: record[field] };
    }
    if (Object.keys(fields).length) change.changed.push({ ...base, fields });
    else if (record.sessionId === sessionId) change.reverified.push(base);
    else change.unverified.push(base);
  }
  return change;
}
