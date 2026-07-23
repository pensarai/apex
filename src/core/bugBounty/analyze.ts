import { createHash } from "node:crypto";
import { isIP } from "node:net";
import {
  type AnalyzeBugBountyListingInput,
  type BugBountyAsset,
  type BugBountyBrief,
  BugBountyBriefSchema,
  type BugBountyPlatform,
  type BugBountyRule,
  type RequiredHeader,
} from "./types";

const MAX_LISTING_BYTES = 2 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 30_000;

export async function analyzeBugBountyListing(
  input: AnalyzeBugBountyListingInput,
): Promise<BugBountyBrief> {
  const listingUrl = validateListingUrl(input.listingUrl);
  const content =
    input.content ??
    (await fetchListingContent(
      listingUrl,
      input.fetchImpl ?? fetch,
      input.abortSignal,
    ));

  if (Buffer.byteLength(content, "utf8") > MAX_LISTING_BYTES) {
    throw new Error(`Bug bounty listing exceeds ${MAX_LISTING_BYTES} bytes`);
  }

  const platform = detectPlatform(listingUrl);
  const text = htmlToText(content);
  const lines = text
    .split(/\n+/)
    .map((line) => line.replace(/\s+/g, " ").trim())
    .filter(Boolean);
  const programName = extractProgramName(content, lines, listingUrl);
  const assets = extractAssets(lines, listingUrl);
  const requiredHeaders = extractRequiredHeaders(lines);
  const rules = extractRules(lines);
  const status = inferStatus(lines);
  const ambiguities: string[] = [];

  if (!assets.some((asset) => asset.inScope)) {
    ambiguities.push("No explicit in-scope asset could be extracted.");
  }
  if (assets.some((asset) => asset.inScope && asset.value.includes("{"))) {
    ambiguities.push(
      "At least one in-scope asset contains an unresolved placeholder.",
    );
  }

  return BugBountyBriefSchema.parse({
    programName,
    platform,
    status,
    source: {
      listingUrl,
      fetchedAt: new Date().toISOString(),
      contentHash: sha256(content),
    },
    assets,
    rules,
    requiredHeaders,
    notes: extractNotes(lines),
    ambiguities,
  });
}

export function detectPlatform(listingUrl: string): BugBountyPlatform {
  const hostname = new URL(listingUrl).hostname.toLowerCase();
  if (hostname === "hackerone.com" || hostname.endsWith(".hackerone.com")) {
    return "hackerone";
  }
  if (hostname === "bugcrowd.com" || hostname.endsWith(".bugcrowd.com")) {
    return "bugcrowd";
  }
  if (hostname === "intigriti.com" || hostname.endsWith(".intigriti.com")) {
    return "intigriti";
  }
  return "generic";
}

function validateListingUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Bug bounty listing URL must use HTTP or HTTPS");
  }
  const hostname = url.hostname.toLowerCase();
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    isPrivateAddress(hostname)
  ) {
    throw new Error("Bug bounty listing URL must be publicly routable");
  }
  url.hash = "";
  return url.toString();
}

function isPrivateAddress(hostname: string): boolean {
  if (isIP(hostname) === 4) {
    const [a, b] = hostname.split(".").map(Number);
    return (
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  if (isIP(hostname) === 6) {
    const lower = hostname.toLowerCase();
    return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd");
  }
  return false;
}

async function fetchListingContent(
  listingUrl: string,
  fetchImpl: typeof fetch,
  parentSignal?: AbortSignal,
): Promise<string> {
  const timeout = AbortSignal.timeout(FETCH_TIMEOUT_MS);
  const signal = parentSignal
    ? AbortSignal.any([parentSignal, timeout])
    : timeout;
  const response = await fetchImpl(listingUrl, {
    redirect: "follow",
    signal,
    headers: { "User-Agent": "pensar-apex-bug-bounty-preflight" },
  });
  if (!response.ok) {
    throw new Error(
      `Unable to fetch bug bounty listing: HTTP ${response.status}`,
    );
  }
  const length = Number(response.headers.get("content-length") ?? 0);
  if (length > MAX_LISTING_BYTES) {
    throw new Error(`Bug bounty listing exceeds ${MAX_LISTING_BYTES} bytes`);
  }
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (
    contentType &&
    !contentType.includes("text/") &&
    !contentType.includes("application/json")
  ) {
    throw new Error(
      `Unsupported bug bounty listing content type: ${contentType}`,
    );
  }
  return await response.text();
}

function htmlToText(content: string): string {
  return decodeHtml(
    content
      .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
      .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
      .replace(/<\/(?:p|div|li|tr|h[1-6]|section|article)>/gi, "\n")
      .replace(/<br\s*\/?\s*>/gi, "\n")
      .replace(/<[^>]+>/g, " "),
  );
}

function decodeHtml(value: string): string {
  const named: Record<string, string> = {
    amp: "&",
    lt: "<",
    gt: ">",
    quot: '"',
    apos: "'",
    nbsp: " ",
  };
  return value.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match, entity) => {
    const lower = String(entity).toLowerCase();
    if (lower.startsWith("#x")) {
      return String.fromCodePoint(Number.parseInt(lower.slice(2), 16));
    }
    if (lower.startsWith("#")) {
      return String.fromCodePoint(Number.parseInt(lower.slice(1), 10));
    }
    return named[lower] ?? match;
  });
}

function extractProgramName(
  content: string,
  lines: string[],
  listingUrl: string,
): string {
  const h1 = content.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i)?.[1];
  const title = content.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1];
  const candidate = h1 ?? title;
  if (candidate) {
    const clean = htmlToText(candidate).replace(/\s+/g, " ").trim();
    if (clean) return clean.slice(0, 200);
  }
  return lines[0]?.slice(0, 200) || new URL(listingUrl).hostname;
}

type ScopeSection = "in" | "out" | "unknown";

function extractAssets(lines: string[], listingUrl: string): BugBountyAsset[] {
  const listingHost = new URL(listingUrl).hostname.toLowerCase();
  const found = new Map<string, BugBountyAsset>();
  let section: ScopeSection = "unknown";

  for (const line of lines) {
    if (/\b(out[ -]of[ -]scope|excluded assets?|not in scope)\b/i.test(line)) {
      section = "out";
    } else if (
      /\b(in[ -]scope|scope and rewards?|eligible assets?|targets?)\b/i.test(
        line,
      )
    ) {
      section = "in";
    }

    const inlineOut =
      /\b(out[ -]of[ -]scope|do not test|excluded|prohibited)\b/i.test(line);
    const inlineIn = /\b(in[ -]scope|eligible|bounty)\b/i.test(line);
    const inScope = inlineOut ? false : inlineIn ? true : section === "in";

    for (const value of extractAssetValues(line)) {
      const normalized = normalizeAssetValue(value);
      if (!normalized || isListingPlatformAsset(normalized, listingHost))
        continue;
      const key = normalized.toLowerCase();
      const asset: BugBountyAsset = {
        value: normalized,
        type: classifyAsset(normalized),
        inScope,
        instructions:
          line.length > normalized.length ? line.slice(0, 500) : undefined,
        sourceExcerpt: line.slice(0, 500),
      };
      const previous = found.get(key);
      if (!previous || (!asset.inScope && previous.inScope))
        found.set(key, asset);
    }
  }

  return [...found.values()];
}

function extractAssetValues(line: string): string[] {
  const values = new Set<string>();
  const urlHosts = new Set<string>();
  for (const match of line.matchAll(/https?:\/\/[^\s<>()\]"']+/gi)) {
    const value = match[0].replace(/[.,;:]+$/, "");
    values.add(value);
    try {
      urlHosts.add(new URL(value).hostname.toLowerCase());
    } catch {
      // The normalizer drops malformed URLs below.
    }
  }
  for (const match of line.matchAll(/\*\.[a-z0-9][a-z0-9.-]+\.[a-z]{2,}/gi)) {
    values.add(match[0]);
  }
  for (const match of line.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\b/g)) {
    values.add(match[0]);
  }
  for (const match of line.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
    values.add(match[0]);
  }
  for (const match of line.matchAll(
    /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi,
  )) {
    if (!urlHosts.has(match[0].toLowerCase())) values.add(match[0]);
  }
  return [...values];
}

function normalizeAssetValue(value: string): string | null {
  const trimmed = value.trim().replace(/[.,;:]+$/, "");
  if (!trimmed) return null;
  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const url = new URL(trimmed);
      url.hash = "";
      return url.toString();
    } catch {
      return null;
    }
  }
  return trimmed.toLowerCase();
}

function isListingPlatformAsset(value: string, listingHost: string): boolean {
  const host = value.startsWith("http")
    ? new URL(value).hostname
    : value.replace(/^\*\./, "");
  return host === listingHost || listingHost.endsWith(`.${host}`);
}

function classifyAsset(value: string): BugBountyAsset["type"] {
  if (/^https?:\/\//i.test(value)) return "url";
  if (value.startsWith("*.")) return "wildcard";
  if (/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(value)) return "cidr";
  if (isIP(value)) return "ip";
  return "domain";
}

function extractRequiredHeaders(lines: string[]): RequiredHeader[] {
  const headers = new Map<string, RequiredHeader>();
  for (const line of lines) {
    if (!/\b(header|required header|user-agent)\b/i.test(line)) continue;
    for (const match of line.matchAll(
      /\b([A-Za-z][A-Za-z0-9-]{2,}):\s*([^,;\s]+(?:\s+[^,;]+)?)/g,
    )) {
      const name = match[1];
      if (!name.includes("-") && name.toLowerCase() !== "authorization")
        continue;
      const rawValue = match[2].trim();
      const value = /^(?:<.*>|\{.*\}|your-|replace-|value$)/i.test(rawValue)
        ? undefined
        : rawValue.slice(0, 500);
      headers.set(name.toLowerCase(), {
        name,
        value,
        sourceExcerpt: line.slice(0, 500),
      });
    }
  }
  return [...headers.values()];
}

function extractRules(lines: string[]): BugBountyRule[] {
  const rules: BugBountyRule[] = [];
  let inRules = false;
  for (const line of lines) {
    if (
      /\b(program rules|rules of engagement|testing requirements?)\b/i.test(
        line,
      )
    ) {
      inRules = true;
      continue;
    }
    if (
      !inRules &&
      !/\b(must|must not|do not|prohibited|forbidden|rate limit|requests? per second|testing window|submit)\b/i.test(
        line,
      )
    ) {
      continue;
    }
    if (line.length < 12 || line.length > 1_000) continue;
    rules.push({
      category: classifyRule(line),
      statement: line,
      sourceExcerpt: line,
    });
    if (rules.length >= 50) break;
  }
  return dedupeByStatement(rules);
}

function classifyRule(line: string): BugBountyRule["category"] {
  if (/rate limit|requests? per second|rps/i.test(line)) return "rate-limit";
  if (/testing window|between \d|business hours|weekends?/i.test(line)) {
    return "testing-window";
  }
  if (
    /do not|must not|prohibited|forbidden|denial of service|social engineering/i.test(
      line,
    )
  ) {
    return "prohibited-action";
  }
  if (/submit|report|disclosure/i.test(line)) return "submission";
  if (/authorization|safe harbou?r|permission/i.test(line))
    return "authorization";
  return "other";
}

function dedupeByStatement(rules: BugBountyRule[]): BugBountyRule[] {
  const seen = new Set<string>();
  return rules.filter((rule) => {
    const key = rule.statement.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function inferStatus(lines: string[]): BugBountyBrief["status"] {
  const head = lines.slice(0, 40).join(" ");
  if (
    /\b(program|engagement) (?:is )?(closed|suspended|paused)\b/i.test(head)
  ) {
    return "closed";
  }
  if (/\b(open|active) (?:bug bounty|program|engagement)\b/i.test(head)) {
    return "open";
  }
  return "unknown";
}

function extractNotes(lines: string[]): string[] {
  return lines
    .filter((line) =>
      /\b(note|known issue|focus area|priority|credentials?)\b/i.test(line),
    )
    .slice(0, 30)
    .map((line) => line.slice(0, 500));
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
