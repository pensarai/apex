import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { readDocumentedTopology } from "../../offSecAgent/tools/documentTopology";
import { topologyToMermaid } from "../../offSecAgent/tools/topologyMermaid";
import {
  diffTopology,
  type LoadedTopology,
  loadTopology,
  seedFromBaseline,
  type TopologyChangeSet,
  type TopologyRecord,
} from "../../offSecAgent/tools/topologyRecords";

/**
 * An update run re-maps a system an earlier run already mapped. It starts
 * from that run's records, is told what to re-verify, and changes the map
 * through the same tools; the change set is computed from the records after.
 */
export type ReconTrigger =
  | {
      kind: "commit";
      /** Connected repository the commits are in. */
      repository: string;
      /** e.g. "abc123..def456". */
      range: string;
      /** Paths changed in the range, relative to the repository root. */
      changedFiles: string[];
    }
  | {
      kind: "schedule";
      /** What changed in the cloud inventory since the baseline, when one was collected. */
      cloudChanges?: string;
    }
  | {
      kind: "scope";
      /** Origins added to the system since the baseline. */
      addedOrigins: string[];
      /** Connected repositories added since the baseline, by name. */
      addedRepositories: string[];
    };

export interface ReconUpdate {
  /** Session root of the run whose map this run updates. */
  baselineSessionRoot: string;
  trigger: ReconTrigger;
}

/** Changes that cannot alter the attack surface: prose, images, licenses. */
const NOT_SURFACE = [
  /\.(md|mdx|rst|txt|png|jpe?g|gif|svg|ico)$/i,
  /(^|\/)(docs?|\.github\/ISSUE_TEMPLATE)\//i,
  /(^|\/)(LICENSE|CHANGELOG|AUTHORS|CODEOWNERS)(\.[a-z]+)?$/i,
];

export function isSurfaceIrrelevant(path: string): boolean {
  return NOT_SURFACE.some((p) => p.test(path));
}

/** A ref as a path: no line suffix, no leading ./, forward slashes. */
function refPath(ref: string): string | undefined {
  if (/^[a-z]+:\/\//i.test(ref)) return undefined;
  const path = ref
    .trim()
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .replace(/:[\d,-]+$/, "")
    .replace(/\/+$/, "");
  return path || undefined;
}

/**
 * Whether a changed file is what an evidence ref points at. Refs come in
 * many shapes — "infra/vpc.ts", "./services/api.py:42", "repos/backend/
 * services/api.py", a directory like "infra/" — so a file matches when one
 * path ends with the other on segment boundaries, or lies inside a cited
 * directory. Over-matching only means re-verifying a bit more.
 */
export function refCitesFile(ref: string, file: string): boolean {
  const a = refPath(ref);
  const b = refPath(file);
  if (!a || !b) return false;
  const endsWith = (long: string, short: string) =>
    long === short || long.endsWith(`/${short}`);
  if (endsWith(a, b) || endsWith(b, a)) return true;
  const dir = ref.trim().endsWith("/") || !/\.[a-z0-9]+$/i.test(a);
  return dir && (b.startsWith(`${a}/`) || b.includes(`/${a}/`));
}

const cites = (record: TopologyRecord, file: string) =>
  Array.isArray(record.evidence) &&
  record.evidence.some(
    (e) =>
      typeof e === "object" &&
      e !== null &&
      typeof (e as { ref?: unknown }).ref === "string" &&
      refCitesFile((e as { ref: string }).ref, file),
  );

export interface ChangeScope {
  components: string[];
  controls: string[];
  flows: string[];
  /** Surface-relevant changed files no record cites: possibly new components, flows, or controls. */
  unmapped: string[];
  /** Changed files that cannot alter the surface. */
  ignored: string[];
}

/** Which records a commit range touches, from the files their evidence cites. */
export function scopeCommit(
  topology: LoadedTopology,
  changedFiles: readonly string[],
): ChangeScope {
  const scope: ChangeScope = {
    components: [],
    controls: [],
    flows: [],
    unmapped: [],
    ignored: [],
  };
  const hit = new Set<string>();
  const visit = (
    records: TopologyRecord[],
    into: string[],
    label: (r: TopologyRecord) => string,
  ) => {
    for (const r of records)
      for (const file of changedFiles)
        if (!isSurfaceIrrelevant(file) && cites(r, file)) {
          hit.add(file);
          if (!into.includes(label(r))) into.push(label(r));
        }
  };
  visit(topology.components, scope.components, (r) => String(r.name));
  visit(topology.controls, scope.controls, (r) => String(r.name));
  visit(topology.flows, scope.flows, (r) => `${r.from} → ${r.to} (${r.label})`);
  for (const file of changedFiles) {
    if (isSurfaceIrrelevant(file)) scope.ignored.push(file);
    else if (!hit.has(file)) scope.unmapped.push(file);
  }
  return scope;
}

const list = (items: readonly string[]) =>
  items.length ? items.map((i) => `- ${i}`).join("\n") : "- none";

/** The prompt section for an update run; the session must already be seeded. */
export function buildUpdateBrief(
  update: ReconUpdate,
  sessionRoot: string,
): string {
  const topology = loadTopology(sessionRoot);
  const mermaid = topologyToMermaid(readDocumentedTopology(sessionRoot));
  const counts = `${topology.boundaries.length} boundaries, ${topology.components.length} components, ${topology.flows.length} flows, ${topology.controls.length} controls`;
  let work: string;
  if (update.trigger.kind === "commit") {
    const scope = scopeCommit(topology, update.trigger.changedFiles);
    work = `Trigger: new commits ${update.trigger.range} in the connected repository "${update.trigger.repository}". Clone it and read the changed files below at the new revision (when the clone has history, git diff ${update.trigger.range} shows each change).

Records whose evidence cites a changed file. A shared file (compose, a router, IaC) is cited by many records and most will be unaffected; check each against the diff and change only those whose facts the diff changes:
Components:
${list(scope.components)}
Controls:
${list(scope.controls)}
Flows:
${list(scope.flows)}

Changed files no record cites — read each for components, flows, or controls that were added or removed:
${list(scope.unmapped)}

Probe live only what these changes affect; the rest of the map stands.`;
  } else if (update.trigger.kind === "scope") {
    work = `Trigger: the system's scope grew. Map what was added as a first run would — probe each new origin, clone each new repository, and document its boundaries, components, flows, controls, and threats with evidence — and connect it to the existing map: the identity providers, datastores, edges, and third parties it shares with what is already documented.

New origins:
${list(update.trigger.addedOrigins)}
New repositories:
${list(update.trigger.addedRepositories)}

Change an existing record only when the new scope changes its facts (a component now also serves a new origin, a control now also covers it).`;
  } else {
    const hosts = topology.components
      .filter(
        (c) =>
          c.exposure === "public" &&
          Array.isArray(c.endpoints) &&
          c.endpoints.length,
      )
      .map((c) => `${c.name}: ${(c.endpoints as string[]).join(", ")}`);
    work = `Trigger: scheduled re-check. The code may not have changed, but the deployment can drift.

Re-probe every public component at its endpoints and update what differs (headers, technology, controls, exposure); retire a component whose host no longer resolves or answers:
${list(hosts)}

Look for hosts and services that appeared since the baseline, within the authorized scope.${
      update.trigger.cloudChanges
        ? `\n\nCloud inventory changes since the baseline:\n${update.trigger.cloudChanges}`
        : ""
    }`;
  }
  return `## Update run
This session starts from the map an earlier run produced (${counts}); every record in it is already documented. Bring the map up to date with the system as it is now — do not rebuild it.

Current map:
\`\`\`mermaid
${mermaid}\`\`\`

${work}

Rules for an update:
- To change a record, call update_record with only the fields that changed and evidence for the change. Every other field stays exactly as written.
- Never rewrite a record whose facts did not change — not to rephrase it, reformat its endpoints, or add detail you could have recorded before. An update's change set should list only what the system changed.
- To rename a record, document it under the new name with renameFrom so it keeps its identity.
- Document what is new with document_*, as usual, with its flows, controls, and threats.
- Threats follow the change: threat-model a new component, update or retire the threats a change opens, closes, or alters, and leave the rest alone.
- Remove something only with retire_record and evidence that it is gone. Never retire a record because you did not look at it again.
- Leave everything else untouched; records you do not revisit stay as they are.
- Finish as usual: review_topology, then create_attack_surface_report.`;
}

export interface UpdateStart {
  brief: string;
  /** Set when there is nothing for the agent to do. */
  skip?: string;
}

/** Seed the session from the baseline and decide what the agent is told. */
export function startUpdate(
  update: ReconUpdate,
  sessionRoot: string,
): UpdateStart {
  seedFromBaseline(sessionRoot, update.baselineSessionRoot);
  if (update.trigger.kind === "commit") {
    const scope = scopeCommit(
      loadTopology(sessionRoot),
      update.trigger.changedFiles,
    );
    if (
      !scope.components.length &&
      !scope.controls.length &&
      !scope.flows.length &&
      !scope.unmapped.length
    )
      return {
        brief: "",
        skip: `No surface-relevant change in ${update.trigger.range}: ${scope.ignored.length} file(s), none that can alter the attack surface.`,
      };
  }
  return { brief: buildUpdateBrief(update, sessionRoot) };
}

/** Write the change set and the updated diagram beside the session's results. */
export function finishUpdate(
  update: ReconUpdate,
  sessionRoot: string,
  sessionId: string,
): { changeSet: TopologyChangeSet; changesPath: string } {
  const changeSet = diffTopology(
    update.baselineSessionRoot,
    sessionRoot,
    sessionId,
  );
  const changesPath = join(sessionRoot, "topology-changes.json");
  writeFileSync(changesPath, JSON.stringify(changeSet, null, 2));
  writeFileSync(
    join(sessionRoot, "topology.mmd"),
    topologyToMermaid(readDocumentedTopology(sessionRoot), { controls: true }),
  );
  return { changeSet, changesPath };
}
