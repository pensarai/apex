import { readFile } from "fs/promises";
import { extname } from "path";
import {
  type AIAuthConfig,
  type AIModel,
  generateObjectResponse,
} from "../../../ai";
import { parseHackerOneJson } from "./hackeroneParser";
import { type BountyReport, BountyReportSchema } from "./types";

const MAX_REPORT_CHARS = 40_000;

/**
 * Where the inbound report originated. Drives parser dispatch:
 *  - `"hackerone"` — try the H1 JSON fast-path first (errors are non-fatal,
 *     falls through to canonical / LLM paths).
 *  - `"auto"` (default) — detect H1-shape JSON heuristically before falling
 *     through.
 */
export type ReportSource = "hackerone" | "auto";

const EXTRACTION_SYSTEM = `You are extracting structured fields from an inbound bug bounty report. The report may be in any format — HackerOne markdown export, Bugcrowd JSON dump, Intigriti report, plaintext email, or copy/paste from a security researcher. Your job is to pull out the canonical fields without inventing information.

Rules:
- If a field is genuinely absent from the report, use a clearly-empty value ("UNKNOWN" for claimedSeverity, an empty array for pocSteps, "" for optional strings).
- Do NOT speculate. If the reporter did not state the attacker model, write "unspecified".
- For affectedUrl, prefer the full URL if present; otherwise use the path. If multiple endpoints are mentioned, pick the one most central to the reproduction steps.
- pocSteps must be a faithful sequence — preserve the order, do not summarise away steps that look redundant.
- vulnerabilityClass should be the reporter's framing (e.g. "Reflected XSS"), not your own re-classification.`;

function isLikelyJson(content: string): boolean {
  const trimmed = content.trim();
  return trimmed.startsWith("{") || trimmed.startsWith("[");
}

function looksLikeHackerOnePayload(raw: string): boolean {
  // Cheap structural signals — substring match avoids parsing JSON twice.
  // Both signals are H1-specific (the JSON:API discriminator + the unique
  // `vulnerability_information` attribute name).
  return (
    raw.includes('"type":"report"') ||
    raw.includes('"type": "report"') ||
    raw.includes('"vulnerability_information"')
  );
}

/**
 * Parse an inbound bug bounty report from disk into a {@link BountyReport}.
 *
 * Strategy (in order, first hit wins):
 *  1. **HackerOne JSON fast-path** — when `source === "hackerone"`, or when
 *     `source === "auto"` (default) and the content has H1 markers. Pure
 *     deterministic mapping — no LLM call, no network.
 *  2. **Canonical JSON validation** — if the file is JSON and already
 *     matches the {@link BountyReportSchema} shape (e.g. a hand-crafted
 *     fixture), use it directly.
 *  3. **LLM extraction** — single `generateObjectResponse` call against the
 *     trimmed body. Handles markdown exports, plaintext emails, copy/paste.
 */
export async function parseReport(opts: {
  filePath: string;
  model: AIModel;
  source?: ReportSource;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
}): Promise<BountyReport> {
  const raw = await readFile(opts.filePath, "utf-8");
  const ext = extname(opts.filePath).toLowerCase();
  const source: ReportSource = opts.source ?? "auto";

  // 1. HackerOne fast-path.
  const tryHackerOne =
    source === "hackerone" ||
    (source === "auto" &&
      (ext === ".json" || isLikelyJson(raw)) &&
      looksLikeHackerOnePayload(raw));

  if (tryHackerOne) {
    const h1 = parseHackerOneJson(raw);
    if (h1) return h1;
  }

  // 2. Canonical JSON validation.
  if (ext === ".json" || isLikelyJson(raw)) {
    const fastPath = tryDirectJsonParse(raw);
    if (fastPath) return fastPath;
  }

  // 3. LLM extraction.
  const content =
    raw.length > MAX_REPORT_CHARS
      ? `${raw.slice(0, MAX_REPORT_CHARS)}\n\n[...truncated — report exceeded ${MAX_REPORT_CHARS} chars]`
      : raw;

  return generateObjectResponse({
    model: opts.model,
    schema: BountyReportSchema,
    system: EXTRACTION_SYSTEM,
    prompt: `Extract the structured fields from the report below.\n\n--- REPORT START ---\n${content}\n--- REPORT END ---`,
    authConfig: opts.authConfig,
    abortSignal: opts.abortSignal,
  });
}

function tryDirectJsonParse(raw: string): BountyReport | null {
  try {
    const parsed = JSON.parse(raw);
    const result = BountyReportSchema.safeParse(parsed);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}
