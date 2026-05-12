import type {
  BountyReport,
  StructuredScopeAsset,
} from "./types";

/**
 * Deterministic parser for HackerOne JSON payloads. Handles both:
 *
 *  - The canonical `GET /reports/{id}` response shape
 *    (`{ data: { type: "report", attributes: {...}, relationships: {...} } }`)
 *  - The `report_created` webhook envelope, where the activity is the top-
 *    level `data` and the report sits inside `relationships.report.data`
 *    (or — in JSON:API style — is referenced by id with the full object in
 *    `included`).
 *
 * Returns `null` if the input is not recognisably a HackerOne payload — the
 * caller falls through to the LLM extraction path. This keeps the happy path
 * deterministic, cheap, and offline-safe.
 *
 * Field mapping (verbatim H1 names → our {@link BountyReport} shape):
 *   - `attributes.title`                  → `title`
 *   - `id`                                → `hackerOneReportId`
 *   - `attributes.severity_rating`        → `claimedSeverity`
 *   - `attributes.vulnerability_information` (markdown) → split into
 *       `description`, `pocSteps`, `pocCurl`, `impact` via section headers
 *   - relationships.weakness  → `vulnerabilityClass` (via `name` attribute)
 *   - relationships.reporter  → `reporterHandle`  (via `username` attribute)
 *   - relationships.structured_scopes → `structuredScopes`
 */
export function parseHackerOneJson(raw: string): BountyReport | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (!isJsonObject(parsed)) return null;

  const included = collectIncluded(parsed);

  // Try direct shape first: { data: { type: "report", ... } }
  const direct = getField(parsed, "data");
  let reportResource = isReportResource(direct) ? direct : null;

  // If the top-level resource is not a report, walk activity relationships.
  if (!reportResource && isJsonObject(direct)) {
    const relReport = getField(getField(direct, "relationships"), "report");
    const relReportData = getField(relReport, "data");
    if (isReportResource(relReportData)) {
      reportResource = relReportData;
    } else if (isJsonObject(relReportData) && typeof relReportData.id === "string") {
      // Webhook envelopes typically reference the report by id with the full
      // object in `included` — resolve via the JSON:API lookup table.
      const id = relReportData.id;
      reportResource = included.report.get(id) ?? null;
    }
  }

  if (!reportResource) return null;
  return mapReportResource(reportResource, included);
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

type JsonObject = Record<string, unknown>;

interface IncludedTable {
  weakness: Map<string, JsonObject>;
  user: Map<string, JsonObject>;
  structuredScope: Map<string, JsonObject>;
  report: Map<string, JsonObject>;
}

function isJsonObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function getField(obj: unknown, key: string): unknown {
  return isJsonObject(obj) ? obj[key] : undefined;
}

function isReportResource(v: unknown): v is JsonObject {
  return isJsonObject(v) && v.type === "report" && isJsonObject(v.attributes);
}

function collectIncluded(top: unknown): IncludedTable {
  const table: IncludedTable = {
    weakness: new Map(),
    user: new Map(),
    structuredScope: new Map(),
    report: new Map(),
  };

  const arr = getField(top, "included");
  if (!Array.isArray(arr)) return table;

  for (const item of arr) {
    if (!isJsonObject(item)) continue;
    if (typeof item.id !== "string") continue;
    const t = item.type;
    if (t === "weakness") table.weakness.set(item.id, item);
    else if (t === "user") table.user.set(item.id, item);
    else if (t === "structured-scope") table.structuredScope.set(item.id, item);
    else if (t === "report") table.report.set(item.id, item);
  }

  return table;
}

function mapReportResource(
  resource: JsonObject,
  included: IncludedTable,
): BountyReport {
  const attrs = (resource.attributes as JsonObject) ?? {};
  const rels = isJsonObject(resource.relationships) ? resource.relationships : {};

  const title = stringField(attrs.title) ?? "(untitled report)";
  const id = typeof resource.id === "string" ? resource.id : undefined;
  const body = stringField(attrs.vulnerability_information) ?? "";

  const claimedSeverity = mapSeverity(stringField(attrs.severity_rating));
  const reporterHandle = resolveReporterHandle(rels, included);
  const weaknessName = resolveWeaknessName(rels, included);
  const structuredScopes = resolveStructuredScopes(rels, included);

  const { description, impact, pocSteps, pocCurl, affectedUrl, attackerModel } =
    extractFromVulnerabilityInformation(body);

  return {
    title,
    reporterHandle,
    claimedSeverity,
    vulnerabilityClass: weaknessName ?? inferClassFromTitle(title),
    affectedUrl: affectedUrl ?? "",
    attackerModel: attackerModel ?? "unspecified",
    description: description || body || "(no description provided)",
    impact: impact ?? "(impact not stated)",
    pocSteps,
    pocCurl,
    references: [],
    hackerOneReportId: id,
    structuredScopes:
      structuredScopes.length > 0 ? structuredScopes : undefined,
  };
}

function stringField(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function mapSeverity(raw: string | undefined): BountyReport["claimedSeverity"] {
  if (!raw) return "UNKNOWN";
  const upper = raw.toUpperCase();
  if (upper === "CRITICAL" || upper === "HIGH" || upper === "MEDIUM" || upper === "LOW") {
    return upper;
  }
  if (upper === "NONE") return "INFORMATIONAL";
  return "UNKNOWN";
}

function resolveReporterHandle(
  rels: JsonObject,
  included: IncludedTable,
): string | undefined {
  const data = getField(rels.reporter, "data");
  if (!isJsonObject(data) || typeof data.id !== "string") return undefined;
  const user = included.user.get(data.id);
  return stringField(getField(user?.attributes, "username"));
}

function resolveWeaknessName(
  rels: JsonObject,
  included: IncludedTable,
): string | undefined {
  const data = getField(rels.weakness, "data");
  if (!isJsonObject(data) || typeof data.id !== "string") return undefined;
  const weakness = included.weakness.get(data.id);
  return stringField(getField(weakness?.attributes, "name"));
}

function resolveStructuredScopes(
  rels: JsonObject,
  included: IncludedTable,
): StructuredScopeAsset[] {
  const data = getField(rels.structured_scopes, "data");
  if (!Array.isArray(data)) return [];

  const out: StructuredScopeAsset[] = [];
  for (const ref of data) {
    if (!isJsonObject(ref) || typeof ref.id !== "string") continue;
    const scope = included.structuredScope.get(ref.id);
    if (!scope) continue;
    const a = isJsonObject(scope.attributes) ? scope.attributes : {};
    const id = stringField(a.asset_identifier);
    const type = stringField(a.asset_type);
    if (!id || !type) continue;
    out.push({
      assetIdentifier: id,
      assetType: type,
      eligibleForSubmission: a.eligible_for_submission === true,
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// Markdown body extraction — HackerOne `vulnerability_information` follows a
// loose convention (## Summary / ## Steps To Reproduce / ## Impact / etc.).
// We extract what we can deterministically; anything missing falls back to
// reasonable defaults in mapReportResource() above.
// ---------------------------------------------------------------------------

interface ExtractedBody {
  description: string;
  impact: string | undefined;
  pocSteps: string[];
  pocCurl: string | undefined;
  affectedUrl: string | undefined;
  attackerModel: string | undefined;
}

const SECTION_HEADER = /^#{1,6}\s+(.+?)\s*$/;

const SECTION_ALIASES: Record<string, "summary" | "steps" | "impact" | "url" | "attacker"> = {
  summary: "summary",
  description: "summary",
  details: "summary",
  "steps to reproduce": "steps",
  "steps to reproduction": "steps",
  reproduction: "steps",
  reproductionsteps: "steps",
  "proof of concept": "steps",
  poc: "steps",
  impact: "impact",
  severity: "impact",
  url: "url",
  "affected url": "url",
  "vulnerable url": "url",
  "attack scenario": "attacker",
  "attacker model": "attacker",
};

function extractFromVulnerabilityInformation(body: string): ExtractedBody {
  if (!body) {
    return {
      description: "",
      impact: undefined,
      pocSteps: [],
      pocCurl: undefined,
      affectedUrl: undefined,
      attackerModel: undefined,
    };
  }

  const sections = splitBySection(body);

  const description = sections.summary ?? body.split(/\n#{1,6}\s/)[0]?.trim() ?? body;
  const stepsBlock = sections.steps;
  const pocSteps = stepsBlock ? extractOrderedSteps(stepsBlock) : [];
  const pocCurl = extractFirstCodeBlock(stepsBlock ?? body);
  const affectedUrl = extractFirstUrl(sections.url ?? stepsBlock ?? body);

  return {
    description,
    impact: sections.impact,
    pocSteps,
    pocCurl,
    affectedUrl,
    attackerModel: sections.attacker,
  };
}

function splitBySection(body: string): Partial<Record<"summary" | "steps" | "impact" | "url" | "attacker", string>> {
  const lines = body.split(/\r?\n/);
  const result: Partial<Record<"summary" | "steps" | "impact" | "url" | "attacker", string>> = {};

  let currentKey: keyof typeof result | null = null;
  let buffer: string[] = [];

  const flush = () => {
    if (currentKey && buffer.length > 0) {
      const text = buffer.join("\n").trim();
      if (text) result[currentKey] = text;
    }
    buffer = [];
  };

  for (const line of lines) {
    const headerMatch = SECTION_HEADER.exec(line);
    if (headerMatch) {
      const normalized = headerMatch[1]!.toLowerCase().trim();
      const key = SECTION_ALIASES[normalized] ?? SECTION_ALIASES[normalized.replace(/[^a-z]+/g, "")];
      flush();
      currentKey = key ?? null;
      continue;
    }
    if (currentKey) buffer.push(line);
  }
  flush();

  return result;
}

function extractOrderedSteps(block: string): string[] {
  const steps: string[] = [];
  const lines = block.split(/\r?\n/);
  let current: string | null = null;

  const isStepStart = (line: string): boolean =>
    /^\s*(?:\d+[.)]|[-*])\s+/.test(line);

  for (const line of lines) {
    if (isStepStart(line)) {
      if (current !== null) steps.push(current.trim());
      current = line.replace(/^\s*(?:\d+[.)]|[-*])\s+/, "");
    } else if (current !== null && line.trim().length > 0) {
      current += ` ${line.trim()}`;
    } else if (current !== null && line.trim().length === 0) {
      steps.push(current.trim());
      current = null;
    }
  }
  if (current !== null) steps.push(current.trim());

  return steps.filter((s) => s.length > 0);
}

function extractFirstCodeBlock(block: string): string | undefined {
  const fenceMatch = /```[a-zA-Z]*\n([\s\S]*?)\n```/.exec(block);
  if (fenceMatch?.[1]) return fenceMatch[1].trim();
  return undefined;
}

function extractFirstUrl(block: string): string | undefined {
  const urlMatch = /https?:\/\/[^\s)"'`]+/.exec(block);
  return urlMatch?.[0];
}

function inferClassFromTitle(title: string): string {
  // Last-resort fallback when weakness relationship is absent. Match a few
  // very common vuln-class keywords; otherwise return the raw title.
  const lower = title.toLowerCase();
  if (/\bxss\b|cross[\s-]?site\s*scripting/.test(lower)) return "Cross-Site Scripting (XSS)";
  if (/sql\s*injection|sqli/.test(lower)) return "SQL Injection";
  if (/\bidor\b/.test(lower)) return "Insecure Direct Object Reference";
  if (/\bssrf\b/.test(lower)) return "Server-Side Request Forgery";
  if (/\brce\b|remote\s*code/.test(lower)) return "Remote Code Execution";
  if (/csrf/.test(lower)) return "Cross-Site Request Forgery";
  if (/path\s*traversal|directory\s*traversal/.test(lower)) return "Path Traversal";
  return title;
}
