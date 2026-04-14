/**
 * Threat Model Benchmark — Markdown Parser
 *
 * Parses the threat model markdown output into a structured ParsedThreatModel.
 * Uses section-header-driven regex. Tolerates formatting deviations gracefully.
 */

import type {
  ParsedThreatModel,
  ParsedFeature,
  ParsedTrustBoundary,
  ParsedAttackerProfile,
  ParsedComponent,
  ParsedDataFlow,
  ParsedSecurityControl,
  ParsedAttackPath,
} from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface Section {
  heading: string;
  body: string;
}

/** Split markdown into ## sections. Returns heading + everything until next ## */
function splitH2(md: string): Section[] {
  const sections: Section[] = [];
  const regex = /^## (.+)$/gm;
  let match: RegExpExecArray | null;
  const starts: { heading: string; index: number }[] = [];

  while ((match = regex.exec(md)) !== null) {
    starts.push({ heading: match[1].trim(), index: match.index });
  }

  for (let i = 0; i < starts.length; i++) {
    const start = starts[i];
    const end = i + 1 < starts.length ? starts[i + 1].index : md.length;
    const body = md.slice(start.index + `## ${start.heading}`.length, end).trim();
    sections.push({ heading: start.heading, body });
  }

  return sections;
}

/** Split a section body into ### subsections */
function splitH3(body: string): Section[] {
  const sections: Section[] = [];
  const regex = /^### (.+)$/gm;
  let match: RegExpExecArray | null;
  const starts: { heading: string; index: number }[] = [];

  while ((match = regex.exec(body)) !== null) {
    starts.push({ heading: match[1].trim(), index: match.index });
  }

  for (let i = 0; i < starts.length; i++) {
    const start = starts[i];
    const end = i + 1 < starts.length ? starts[i + 1].index : body.length;
    const content = body
      .slice(start.index + `### ${start.heading}`.length, end)
      .trim();
    sections.push({ heading: start.heading, body: content });
  }

  return sections;
}

/** Find a section by heading (case-insensitive, whitespace-normalized) */
function findSection(
  sections: Section[],
  ...names: string[]
): Section | undefined {
  const normalize = (s: string) => s.toLowerCase().replace(/[\s_-]+/g, " ");
  for (const name of names) {
    const target = normalize(name);
    const found = sections.find((s) => normalize(s.heading).includes(target));
    if (found) return found;
  }
  return undefined;
}

/** Extract `- **Key:** Value` lines from body text */
function extractKeyValue(body: string, key: string): string | undefined {
  const re = new RegExp(
    `\\*\\*${key}:?\\*\\*\\s*(.+)`,
    "im",
  );
  const m = body.match(re);
  return m?.[1]?.trim();
}

/** Parse a markdown table into rows of cell arrays. Skips header separator. */
function parseTable(body: string): string[][] {
  const lines = body.split("\n").filter((l) => l.trim().startsWith("|"));
  if (lines.length < 2) return [];

  const rows: string[][] = [];
  for (let i = 0; i < lines.length; i++) {
    const cells = lines[i]
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    // Skip separator row (all dashes/colons)
    if (cells.every((c) => /^[-:]+$/.test(c))) continue;
    rows.push(cells);
  }

  // First row is header — return data rows only
  return rows.slice(1);
}

/** Extract numbered list items (1. text, 2. text, ...) */
function parseNumberedList(body: string): string[] {
  const items: string[] = [];
  const re = /^\d+\.\s+(.+)$/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    items.push(m[1].trim());
  }
  return items;
}

/** Extract bullet list items (- text) */
function parseBulletList(body: string): string[] {
  const items: string[] = [];
  const re = /^[-*]\s+(.+)$/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    items.push(m[1].trim());
  }
  return items;
}

// ---------------------------------------------------------------------------
// Section Parsers
// ---------------------------------------------------------------------------

function parseMetadata(
  md: string,
  appContextBody: string,
): ParsedThreatModel["metadata"] {
  const meta: ParsedThreatModel["metadata"] = {};

  // Top-level metadata (before ## sections)
  const genMatch = md.match(/\*\*Generated:\*\*\s*(.+)/i);
  if (genMatch) meta.generated = genMatch[1].trim();
  const cbMatch = md.match(/\*\*Codebase:\*\*\s*(.+)/i);
  if (cbMatch) meta.codebase = cbMatch[1].trim();
  const rtMatch = md.match(/\*\*Repo Type:\*\*\s*(.+)/i);
  if (rtMatch) meta.repoType = rtMatch[1].trim();
  const pmMatch = md.match(/\*\*Package Manager:\*\*\s*(.+)/i);
  if (pmMatch) meta.packageManager = pmMatch[1].trim();

  // From Application Context > Identity
  if (appContextBody) {
    const identitySubs = splitH3(appContextBody);
    const identity = findSection(identitySubs, "identity");
    if (identity) {
      meta.type = extractKeyValue(identity.body, "Type");
      meta.domain = extractKeyValue(identity.body, "Domain");
      meta.description = extractKeyValue(identity.body, "Description");
      meta.users = extractKeyValue(identity.body, "Users");
    }
  }

  return meta;
}

function parseFeatures(body: string): ParsedFeature[] {
  const rows = parseTable(body);
  return rows.map((cells) => ({
    name: (cells[0] ?? "").replace(/\*\*/g, "").trim(),
    securityRelevance: cells[1] ?? "",
    privilegedOps: cells[2] ?? "",
    dataHandled: cells[3] ?? "",
  }));
}

function parseTrustBoundaries(body: string): ParsedTrustBoundary[] {
  const subs = splitH3(body).length > 0 ? splitH3(body) : [];

  // Try #### subsections within the body (some models use ####)
  if (subs.length === 0) {
    const h4Re = /^####\s+(.+)$/gm;
    let m: RegExpExecArray | null;
    const h4Starts: { heading: string; index: number }[] = [];
    while ((m = h4Re.exec(body)) !== null) {
      h4Starts.push({ heading: m[1].trim(), index: m.index });
    }
    for (let i = 0; i < h4Starts.length; i++) {
      const start = h4Starts[i];
      const end = i + 1 < h4Starts.length ? h4Starts[i + 1].index : body.length;
      subs.push({
        heading: start.heading,
        body: body.slice(start.index + `#### ${start.heading}`.length, end).trim(),
      });
    }
  }

  return subs.map((s) => ({
    name: s.heading,
    description: s.body.split("\n")[0] ?? "",
    inputSources: extractKeyValue(s.body, "Input Sources"),
    crossesTo: extractKeyValue(s.body, "Crosses To"),
  }));
}

function parseAttackerProfiles(body: string): ParsedAttackerProfile[] {
  const subs = splitH3(body).length > 0 ? splitH3(body) : [];

  // Fall back to #### headings
  if (subs.length === 0) {
    const h4Re = /^####\s+(.+)$/gm;
    let m: RegExpExecArray | null;
    const h4Starts: { heading: string; index: number }[] = [];
    while ((m = h4Re.exec(body)) !== null) {
      h4Starts.push({ heading: m[1].trim(), index: m.index });
    }
    for (let i = 0; i < h4Starts.length; i++) {
      const start = h4Starts[i];
      const end = i + 1 < h4Starts.length ? h4Starts[i + 1].index : body.length;
      subs.push({
        heading: start.heading,
        body: body.slice(start.index + `#### ${start.heading}`.length, end).trim(),
      });
    }
  }

  return subs.map((s) => {
    const desc = s.body.split("\n").filter((l) => l.trim() && !l.startsWith("-") && !l.startsWith("*"))[0] ?? "";
    return {
      name: s.heading,
      description: desc,
      skillLevel: extractKeyValue(s.body, "Skill Level"),
      controls: parseBulletList(
        s.body.slice(s.body.search(/\*\*Controls?:\*\*/i) || 0),
      ).slice(0, 10),
      goals: parseBulletList(
        s.body.slice(s.body.search(/\*\*Goals?:\*\*/i) || 0),
      ).slice(0, 10),
    };
  });
}

function parseComponents(body: string): ParsedComponent[] {
  const rows = parseTable(body);
  return rows.map((cells) => ({
    id: cells[0] ?? "",
    name: cells[1] ?? "",
    type: cells[2] ?? "",
    technology: cells[3] ?? "",
    trustBoundary: cells[4] ?? "",
  }));
}

function parseDataFlows(body: string): ParsedDataFlow[] {
  const rows = parseTable(body);
  return rows.map((cells) => ({
    id: cells[0] ?? "",
    from: cells[1] ?? "",
    to: cells[2] ?? "",
    protocol: cells[3] ?? "",
    dataClassification: cells[4] ?? "",
    authenticated: cells[5] ?? "",
    encrypted: cells[6] ?? "",
  }));
}

function parseSecurityControls(body: string): ParsedSecurityControl[] {
  const subs = splitH3(body);
  return subs.map((s) => {
    // Extract SC-ID from heading: "SC-1: Control Name" or "SC-01: Control Name"
    const idMatch = s.heading.match(/(SC-\d+)/i);
    const nameMatch = s.heading.match(/SC-\d+:\s*(.+)/i);
    return {
      id: idMatch?.[1] ?? s.heading,
      name: nameMatch?.[1]?.trim() ?? s.heading,
      type: extractKeyValue(s.body, "Type") ?? "",
      effectiveness: extractKeyValue(s.body, "Effectiveness") ?? "",
      scope: extractKeyValue(s.body, "Scope") ?? "",
      implementation: extractKeyValue(s.body, "Implementation") ?? "",
      gaps: extractKeyValue(s.body, "Gaps") ?? "",
    };
  });
}

function parseAttackPaths(body: string): ParsedAttackPath[] {
  const subs = splitH3(body);
  return subs.map((s) => {
    // Extract ID + title + severity from heading
    // Format: "AP-1: Title [SEVERITY]" or "AP-01: Title Including Entry Point [High]"
    const idMatch = s.heading.match(/(AP-\d+)/i);
    const sevMatch = s.heading.match(/\[(\w+)\]\s*$/i);
    const titleMatch = s.heading.match(/AP-\d+:\s*(.+?)(?:\s*\[\w+\])?\s*$/i);

    const id = idMatch?.[1] ?? s.heading;
    const title = titleMatch?.[1]?.trim() ?? s.heading;
    const severity =
      sevMatch?.[1] ??
      extractKeyValue(s.body, "Severity") ??
      "";

    // Extract mechanism steps
    const mechanismStart = s.body.search(/\*\*Mechanism:?\*\*/i);
    const impactStart = s.body.search(/\*\*Impact:?\*\*/i);
    let mechanism: string[] = [];
    if (mechanismStart >= 0) {
      const end = impactStart > mechanismStart ? impactStart : s.body.length;
      mechanism = parseNumberedList(s.body.slice(mechanismStart, end));
    }

    // Extract impact
    let impact = "";
    if (impactStart >= 0) {
      const afterImpact = s.body.slice(impactStart);
      const nextSection = afterImpact.search(/^####\s/m);
      const impactText =
        nextSection > 0
          ? afterImpact.slice(0, nextSection)
          : afterImpact.split("\n").slice(0, 5).join("\n");
      impact = impactText
        .replace(/\*\*Impact:?\*\*\s*/i, "")
        .trim();
    }

    // Parse #### subsections within the attack path
    const h4Re = /^####\s+(.+)$/gm;
    let m: RegExpExecArray | null;
    const h4Map: Record<string, string> = {};
    const h4Starts: { heading: string; index: number }[] = [];
    while ((m = h4Re.exec(s.body)) !== null) {
      h4Starts.push({ heading: m[1].trim().toLowerCase(), index: m.index });
    }
    for (let i = 0; i < h4Starts.length; i++) {
      const start = h4Starts[i];
      const end =
        i + 1 < h4Starts.length ? h4Starts[i + 1].index : s.body.length;
      h4Map[start.heading] = s.body
        .slice(start.index + `#### ${start.heading}`.length + 4, end)
        .trim();
    }

    const findH4 = (...names: string[]) => {
      for (const n of names) {
        const key = Object.keys(h4Map).find((k) => k.includes(n.toLowerCase()));
        if (key) return h4Map[key];
      }
      return "";
    };

    const preconditionsText = findH4("precondition");
    const existingControlsText = findH4("existing control");
    const controlGapsText = findH4("control gap");
    const pentestGuidanceText = findH4("pentest", "test guidance");

    return {
      id,
      title,
      severity,
      attackerProfile: extractKeyValue(s.body, "Attacker Profile") ?? "",
      entryPoint: extractKeyValue(s.body, "Entry Point") ?? "",
      affectedFeatures: extractKeyValue(s.body, "Affected Features") ?? "",
      mechanism,
      impact,
      preconditions: parseBulletList(preconditionsText),
      existingControls: parseBulletList(existingControlsText),
      controlGaps: parseBulletList(controlGapsText),
      pentestGuidance: pentestGuidanceText,
      subsectionsPresent: {
        mechanism: mechanism.length > 0,
        impact: impact.length > 0,
        preconditions: preconditionsText.length > 0,
        existingControls: existingControlsText.length > 0,
        controlGaps: controlGapsText.length > 0,
        pentestGuidance: pentestGuidanceText.length > 0,
      },
    };
  });
}

function parseSummary(
  body: string,
): ParsedThreatModel["summary"] {
  const summary: ParsedThreatModel["summary"] = { bySeverity: {} };
  const rows = parseTable(body);
  for (const cells of rows) {
    const label = (cells[0] ?? "").toLowerCase();
    const value = parseInt(cells[1] ?? "", 10);
    if (isNaN(value)) continue;

    if (label.includes("component")) summary.components = value;
    else if (label.includes("data flow")) summary.dataFlows = value;
    else if (label.includes("attack path") && !label.includes("severity"))
      summary.attackPaths = value;
    else if (label.includes("critical")) summary.bySeverity["critical"] = value;
    else if (label.includes("high")) summary.bySeverity["high"] = value;
    else if (label.includes("medium")) summary.bySeverity["medium"] = value;
    else if (label.includes("low")) summary.bySeverity["low"] = value;
  }
  return summary;
}

// ---------------------------------------------------------------------------
// Main Parser
// ---------------------------------------------------------------------------

export function parseThreatModelMarkdown(md: string): ParsedThreatModel {
  const h2Sections = splitH2(md);
  const sectionsFound = h2Sections.map((s) => s.heading);

  // Find key sections
  const appContext = findSection(h2Sections, "application context");
  const deployModel = findSection(h2Sections, "deployment model");
  const compSection = findSection(h2Sections, "system components", "components");
  const tbSection = findSection(h2Sections, "trust boundaries");
  const dfSection = findSection(h2Sections, "data flow");
  const scSection = findSection(h2Sections, "security control");
  const apSection = findSection(h2Sections, "attack path");
  const sumSection = findSection(h2Sections, "summary");

  // Parse Application Context subsections
  const acSubs = appContext ? splitH3(appContext.body) : [];
  const featSection = findSection(acSubs, "features", "capabilities");
  const tbInAc = findSection(acSubs, "trust boundar");
  const profSection = findSection(acSubs, "attacker profile");

  return {
    raw: md,
    metadata: parseMetadata(md, appContext?.body ?? ""),
    features: featSection ? parseFeatures(featSection.body) : [],
    trustBoundaries: tbInAc
      ? parseTrustBoundaries(tbInAc.body)
      : tbSection
        ? parseTrustBoundaries(tbSection.body)
        : [],
    attackerProfiles: profSection
      ? parseAttackerProfiles(profSection.body)
      : [],
    deploymentModel: deployModel?.body ?? "",
    components: compSection ? parseComponents(compSection.body) : [],
    dataFlows: dfSection ? parseDataFlows(dfSection.body) : [],
    securityControls: scSection ? parseSecurityControls(scSection.body) : [],
    attackPaths: apSection ? parseAttackPaths(apSection.body) : [],
    summary: sumSection
      ? parseSummary(sumSection.body)
      : { bySeverity: {} },
    sectionsFound,
  };
}
