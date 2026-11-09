import type { TopologyRecord } from "./topologyRecords";

/**
 * Deterministic signals that two records of the same kind describe one
 * thing. They only ask: a match makes the agent update the existing record,
 * merge the two, or say they are distinct — it never merges on its own.
 */

/** Words that tell deployments or roles apart in prose but not in identity. */
const NOISE = new Set([
  "the",
  "a",
  "an",
  "of",
  "and",
  "for",
  "on",
  "in",
  "with",
  "production",
  "prod",
  "live",
  "main",
  "primary",
  "service",
  "services",
  "instance",
  "server",
  "cluster",
]);

function words(name: string): Set<string> {
  return new Set(
    name
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((w) => w && !NOISE.has(w))
      // Fold plurals: caches/cache, sandboxes/sandbox, queues/queue.
      .map((w) => (w.length > 3 ? w.replace(/s$/, "").replace(/e$/, "") : w)),
  );
}

/** One name's words are all in the other's, and it has at least two. */
export function namesOverlap(a: string, b: string): boolean {
  const x = words(a);
  const y = words(b);
  const [small, large] = x.size <= y.size ? [x, y] : [y, x];
  if (small.size === 0) return false;
  if (small.size < 2 && small.size !== large.size) return false;
  return [...small].every((w) => large.has(w));
}

function hosts(record: TopologyRecord): Set<string> {
  // App-link schemes (example://pay) are not network places, and one host can
  // route paths to different services (/v1 legacy, /v2 its successor), so the
  // path is part of the endpoint.
  const out = new Set<string>();
  for (const e of Array.isArray(record.endpoints) ? record.endpoints : []) {
    const text = String(e).trim();
    const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(text)?.[1]?.toLowerCase();
    if (scheme && scheme !== "http" && scheme !== "https") continue;
    try {
      const url = new URL(scheme ? text : `http://${text}`);
      out.add(`${url.host.toLowerCase()}${url.pathname.replace(/\/+$/, "")}`);
    } catch {
      // An endpoint that is not a URL or host (a description) has no host to compare.
    }
  }
  return out;
}

const ACCOUNT_ID = /\b\d{12}\b/g;
const accountIds = (r: TopologyRecord) =>
  new Set(`${r.name ?? ""} ${r.description ?? ""}`.match(ACCOUNT_ID) ?? []);

const distinct = (a: TopologyRecord, b: TopologyRecord) => {
  const said = (r: TopologyRecord, other: TopologyRecord) =>
    Array.isArray(r.distinctFrom) &&
    r.distinctFrom.some(
      (n) => String(n).toLowerCase() === String(other.name).toLowerCase(),
    );
  return said(a, b) || said(b, a);
};

/** Why `a` and `b` (same kind) look like one thing, or undefined. */
export function duplicateReason(
  kind: "boundary" | "component",
  a: TopologyRecord,
  b: TopologyRecord,
): string | undefined {
  if (a.id === b.id || a.kind !== b.kind || distinct(a, b)) return undefined;
  // Clients do not answer on hosts; two apps that call the same APIs are not one app.
  if (kind === "component" && a.kind !== "client") {
    const [x, y] = [hosts(a), hosts(b)];
    const shared = [...x].filter((h) => y.has(h));
    if (shared.length) return `both answer on ${shared.join(", ")}`;
    // Known, different hosts are different things whatever they are called.
    if (x.size && y.size) return undefined;
  }
  // Boundaries under different parents (a region in each of two accounts) are different places.
  const sameParent =
    kind === "component" ||
    String(a.parent ?? "").toLowerCase() ===
      String(b.parent ?? "").toLowerCase();
  if (sameParent && namesOverlap(String(a.name), String(b.name)))
    return "their names describe the same thing";
  if (kind === "boundary" && a.kind === "cloud-account") {
    const [x, y] = [accountIds(a), accountIds(b)];
    const sameProvider =
      !a.provider || !b.provider || a.provider === b.provider;
    const told = x.size > 0 && y.size > 0;
    if (sameProvider && !(told && [...x].every((id) => !y.has(id))))
      return told
        ? "they name the same account id"
        : "a second account of the same provider with no account id to tell them apart";
  }
  return undefined;
}

/** Existing records the candidate looks like, with the reason. */
export function likelyDuplicates(
  kind: "boundary" | "component",
  candidate: TopologyRecord,
  existing: readonly TopologyRecord[],
): { record: TopologyRecord; reason: string }[] {
  return existing.flatMap((record) => {
    const reason = duplicateReason(kind, candidate, record);
    return reason ? [{ record, reason }] : [];
  });
}

/** Every likely-duplicate pair in a set of records of one kind. */
export function duplicatePairs(
  kind: "boundary" | "component",
  records: readonly TopologyRecord[],
): { a: TopologyRecord; b: TopologyRecord; reason: string }[] {
  const pairs: { a: TopologyRecord; b: TopologyRecord; reason: string }[] = [];
  for (let i = 0; i < records.length; i++)
    for (let j = i + 1; j < records.length; j++) {
      const reason = duplicateReason(
        kind,
        records[i] as TopologyRecord,
        records[j] as TopologyRecord,
      );
      if (reason)
        pairs.push({
          a: records[i] as TopologyRecord,
          b: records[j] as TopologyRecord,
          reason,
        });
    }
  return pairs;
}
