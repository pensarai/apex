import { createHash } from "node:crypto";

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [],
    cell = "",
    quoted = false,
    closed = false;
  text = text.replace(/^\uFEFF/, "");
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
        closed = true;
      } else cell += c;
    } else if (c === "," || c === "\n" || c === "\r") {
      row.push(cell);
      cell = "";
      closed = false;
      if (c !== ",") {
        rows.push(row);
        row = [];
        if (c === "\r" && text[i + 1] === "\n") i++;
      }
    } else if (c === '"' && !cell && !closed) quoted = true;
    else {
      if (closed || c === '"') throw new Error("Malformed CSV quoting");
      cell += c;
    }
  }
  if (quoted) throw new Error("Unclosed CSV field");
  if (cell || row.length || closed) rows.push([...row, cell]);
  return rows;
}

export function csv(rows: string[][]): string {
  return `${rows
    .map((row) =>
      row
        .map((cell) =>
          /[",\r\n]/.test(cell) ? `"${cell.replaceAll('"', '""')}"` : cell,
        )
        .join(","),
    )
    .join("\n")}\n`;
}

export interface ScopeItem {
  id: string;
  domain: string;
  origin: string;
}

export function loadScope(text: string) {
  const items: ScopeItem[] = [];
  const seen = new Set<string>();
  let inputRows = 0;
  for (const row of parseCsv(text)) {
    const value = row[0]?.trim();
    if (row.slice(1).some((cell) => cell.trim()))
      throw new Error("Scope CSV must have one populated column");
    if (!value || /^(domain|hostname|url)$/i.test(value)) continue;
    if (/\s/.test(value)) throw new Error("Whitespace inside scope hostname");
    const url = new URL(value.includes("://") ? value : `https://${value}`);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.port ||
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      url.hostname.includes("*")
    )
      throw new Error(
        `Expected a concrete hostname or HTTP(S) origin: ${value}`,
      );
    const domain = url.hostname.toLowerCase().replace(/\.$/, "");
    if (!/^[a-z0-9_][a-z0-9_.-]*[a-z0-9]$/i.test(domain))
      throw new Error(`Invalid host: ${value}`);
    inputRows++;
    if (seen.has(domain)) continue;
    seen.add(domain);
    items.push({
      id: createHash("sha256").update(domain).digest("hex").slice(0, 16),
      domain,
      origin: `https://${domain}`,
    });
  }
  if (!items.length) throw new Error("Empty scope");
  return { items, inputRows, duplicates: inputRows - items.length };
}

export const TRACKER_COLUMNS = [
  "id",
  "domain",
  "status",
  "component_ids",
  "evidence_refs",
  "reason",
];
export const TRACKER_STATUSES = [
  "pending",
  "in_progress",
  "assessed",
  "covered_by_shared_model",
  "blocked",
  "excluded",
];

export function seedTracker(items: ScopeItem[]): string {
  return csv([
    TRACKER_COLUMNS,
    ...items.map((item) => [item.id, item.domain, "pending", "", "", ""]),
  ]);
}

export function inspectTracker(text: string, items: ScopeItem[]) {
  const [header, ...data] = parseCsv(text);
  if (JSON.stringify(header) !== JSON.stringify(TRACKER_COLUMNS))
    throw new Error("Tracker columns changed");
  const expected = new Map(items.map((item) => [item.id, item.domain]));
  const seen = new Set<string>();
  const errors: string[] = [];
  const rows = data
    .filter((row) => row.some(Boolean))
    .map((row) => {
      const [
        id = "",
        domain = "",
        status = "",
        components = "",
        evidence = "",
        reason = "",
      ] = row;
      if (row.length !== TRACKER_COLUMNS.length)
        errors.push(`Wrong column count: ${id}`);
      if (expected.get(id) !== domain)
        errors.push(`Unknown or changed scope row: ${id}`);
      if (seen.has(id)) errors.push(`Duplicate row: ${id}`);
      seen.add(id);
      if (!TRACKER_STATUSES.includes(status))
        errors.push(`Invalid status: ${id}`);
      if (
        ["assessed", "covered_by_shared_model"].includes(status) &&
        (!components.trim() || !evidence.trim() || !reason.trim())
      )
        errors.push(`Unsupported assessment fields: ${id}`);
      if (
        ["blocked", "excluded"].includes(status) &&
        (!reason.trim() || !evidence.trim())
      )
        errors.push(`Missing limitation explanation: ${id}`);
      return { id, domain, status, components, evidence, reason };
    });
  for (const id of expected.keys())
    if (!seen.has(id)) errors.push(`Missing row: ${id}`);
  return {
    rows,
    errors,
    pending: rows.filter((r) => ["pending", "in_progress"].includes(r.status))
      .length,
  };
}
