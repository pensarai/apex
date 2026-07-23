import { createHash } from "node:crypto";
import {
  type BugBountyAsset,
  type BugBountyBrief,
  type CompileEngagementPolicyOptions,
  type EngagementPolicy,
  EngagementPolicySchema,
} from "./types";

export function compileEngagementPolicy(
  brief: BugBountyBrief,
  options: CompileEngagementPolicyOptions = {},
): EngagementPolicy {
  const excludedTargets = brief.assets.filter((asset) => !asset.inScope);
  const allowedTargets = brief.assets.filter(
    (asset) =>
      asset.inScope &&
      !excludedTargets.some((excluded) => assetCoveredBy(asset, excluded)),
  );
  const configuredHeaders = lowerCaseRecord(options.configuredHeaders ?? {});
  const requiredHeaders: Record<string, string> = {};
  const blockers = [...brief.ambiguities];

  for (const header of brief.requiredHeaders) {
    const value = header.value ?? configuredHeaders[header.name.toLowerCase()];
    if (value) requiredHeaders[header.name] = value;
    else
      blockers.push(
        `Required header "${header.name}" has no configured value.`,
      );
  }
  if (brief.status === "closed")
    blockers.push("The program is closed or suspended.");
  if (allowedTargets.length === 0)
    blockers.push("No executable in-scope targets remain.");

  const allowedHosts = [
    ...new Set(
      allowedTargets.flatMap((asset) => {
        const host = assetHostname(asset);
        return host ? [host] : [];
      }),
    ),
  ];
  const requestsPerSecond = effectiveRateLimit(brief);
  const guidance = buildGuidance(brief, allowedTargets, excludedTargets);
  const base = {
    version: "1" as const,
    listingUrl: brief.source.listingUrl,
    listingContentHash: brief.source.contentHash,
    platform: brief.platform,
    programName: brief.programName,
    allowedTargets,
    excludedTargets,
    allowedHosts,
    requiredHeaders,
    requestsPerSecond,
    rules: brief.rules,
    guidance,
    blockers: [...new Set(blockers)],
    canExecute: blockers.length === 0,
  };
  return EngagementPolicySchema.parse({
    ...base,
    policyHash: hashCanonical(base),
  });
}

function effectiveRateLimit(brief: BugBountyBrief): number | undefined {
  const rates = brief.rules.flatMap((rule) => {
    if (rule.category !== "rate-limit") return [];
    const match = rule.statement.match(
      /(\d+(?:\.\d+)?)\s*(?:requests?|reqs?)\s*(?:per|\/)\s*(second|sec(?:ond)?s?|minute|min(?:ute)?s?|hour|hours?)/i,
    );
    if (!match) return [];
    const amount = Number(match[1]);
    const unit = match[2]?.toLowerCase() ?? "second";
    const divisor = unit.startsWith("min")
      ? 60
      : unit.startsWith("hour")
        ? 3600
        : 1;
    return [amount / divisor];
  });
  return rates.length > 0 ? Math.min(...rates) : undefined;
}

function assetCoveredBy(
  asset: BugBountyAsset,
  exclusion: BugBountyAsset,
): boolean {
  const assetValue = asset.value.toLowerCase();
  const exclusionValue = exclusion.value.toLowerCase();
  if (assetValue === exclusionValue) return true;
  const assetHost = assetHostname(asset);
  const excludedHost = assetHostname(exclusion);
  if (!assetHost || !excludedHost) return false;
  if (exclusion.type === "wildcard") {
    return assetHost === excludedHost || assetHost.endsWith(`.${excludedHost}`);
  }
  if (exclusion.type === "url" && asset.type === "url") {
    return assetValue.startsWith(exclusionValue);
  }
  return false;
}

export function assetHostname(asset: BugBountyAsset): string | null {
  if (asset.type === "url") {
    try {
      return new URL(asset.value).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
  if (
    asset.type === "domain" ||
    asset.type === "wildcard" ||
    asset.type === "ip"
  ) {
    return asset.value.replace(/^\*\./, "").toLowerCase();
  }
  return null;
}

function buildGuidance(
  brief: BugBountyBrief,
  allowed: BugBountyAsset[],
  excluded: BugBountyAsset[],
): string {
  const sections = [
    `Bug bounty program: ${brief.programName}`,
    `Approved in-scope assets:\n${allowed.map((asset) => `- ${asset.value}`).join("\n")}`,
  ];
  if (excluded.length > 0) {
    sections.push(
      `Explicitly excluded assets (never test):\n${excluded
        .map((asset) => `- ${asset.value}`)
        .join("\n")}`,
    );
  }
  if (brief.rules.length > 0) {
    sections.push(
      `Rules of engagement:\n${brief.rules
        .map((rule) => `- ${rule.statement}`)
        .join("\n")}`,
    );
  }
  sections.push(
    "Prioritize high-impact and critical attack chains, but document every validated finding. Do not perform destructive actions, denial-of-service testing, credential stuffing, or social engineering.",
  );
  return sections.join("\n\n");
}

function lowerCaseRecord(
  input: Record<string, string>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).map(([key, value]) => [key.toLowerCase(), value]),
  );
}

function hashCanonical(value: unknown): string {
  return createHash("sha256").update(stableStringify(value)).digest("hex");
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => `${JSON.stringify(key)}:${stableStringify(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
