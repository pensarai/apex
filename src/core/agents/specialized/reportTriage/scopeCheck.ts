import { z } from "zod";
import {
  type AIAuthConfig,
  type AIModel,
  generateObjectResponse,
} from "../../../ai";
import {
  extractHostname,
  isHostAllowed,
} from "../../offSecAgent/tools/scopeGuard";
import type {
  BountyReport,
  ProgramContext,
  ScopeCheckResult,
  StructuredScopeAsset,
} from "./types";

const POLICY_CHECK_SYSTEM = `You are evaluating whether an inbound bug bounty report falls within the program's stated scope and engagement rules.

You will receive:
- The structured report (title, affected URL, vulnerability class, description).
- Optional scope.md content (the program's in-scope / out-of-scope rules).
- Optional engagement.md content (excluded vulnerability classes, accepted risks, rules of engagement).

Decide whether the report is within scope.

Rules:
- If both scope.md and engagement.md are absent, return inScope=true with reason "no policy files present — defaulting to in-scope".
- If the report's vulnerability class is explicitly excluded (e.g. "self-XSS", "rate limiting on public endpoints", "best-practice findings without impact"), return inScope=false and quote the rule.
- If the report's affected component is explicitly out-of-scope (e.g. "marketing site", "third-party dependencies", "staging environments"), return inScope=false and quote the rule.
- If the policy is silent on the report's class/component, return inScope=true.
- The "reason" field must be one short sentence. When out of scope, quote the relevant policy line verbatim.`;

const PolicyCheckSchema = z.object({
  inScope: z.boolean(),
  reason: z.string(),
});

export async function checkScope(opts: {
  report: BountyReport;
  programContext: ProgramContext;
  allowedHosts: string[];
  model: AIModel;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
}): Promise<ScopeCheckResult> {
  const { hostInScope, hostScopeSource, hostReason } = checkHostScope({
    affectedUrl: opts.report.affectedUrl,
    allowedHosts: opts.allowedHosts,
    structuredScopes: opts.report.structuredScopes,
  });

  if (!hostInScope) {
    return {
      inScope: false,
      hostInScope: false,
      policyInScope: false,
      hostScopeSource,
      reason: hostReason,
    };
  }

  const { scope, engagement } = opts.programContext;
  if (!scope && !engagement) {
    return {
      inScope: true,
      hostInScope: true,
      policyInScope: true,
      hostScopeSource,
      reason: "no policy files present — defaulting to in-scope",
    };
  }

  const policy = await generateObjectResponse({
    model: opts.model,
    schema: PolicyCheckSchema,
    system: POLICY_CHECK_SYSTEM,
    prompt: buildPolicyPrompt(opts.report, scope, engagement),
    authConfig: opts.authConfig,
    abortSignal: opts.abortSignal,
  });

  return {
    inScope: policy.inScope,
    hostInScope: true,
    policyInScope: policy.inScope,
    hostScopeSource,
    reason: policy.reason,
  };
}

interface HostScopeOutcome {
  hostInScope: boolean;
  hostScopeSource: ScopeCheckResult["hostScopeSource"];
  hostReason: string;
}

function checkHostScope(opts: {
  affectedUrl: string;
  allowedHosts: string[];
  structuredScopes: StructuredScopeAsset[] | undefined;
}): HostScopeOutcome {
  const trimmed = opts.affectedUrl.trim();

  // Path-only references (`/api/users/{id}`) cannot be host-checked here —
  // they pass and defer to the policy layer. `parseTargetUrl` would
  // silently prepend `https://` and produce a meaningless hostname.
  if (trimmed.startsWith("/") && !trimmed.startsWith("//")) {
    return {
      hostInScope: true,
      hostScopeSource:
        opts.structuredScopes && opts.structuredScopes.length > 0
          ? "structured-scopes"
          : opts.allowedHosts.length > 0
            ? "session-allowed-hosts"
            : "none",
      hostReason: "path-only reference — host check deferred to policy layer",
    };
  }

  // Prefer H1-declared structured scopes when present — they came from the
  // program's official scope list and are authoritative.
  if (opts.structuredScopes && opts.structuredScopes.length > 0) {
    const allowed = deriveAllowedHostsFromStructuredScopes(
      opts.structuredScopes,
    );
    if (allowed.length === 0) {
      // The program has structured_scopes but none of them are URL-typed
      // assets. Fall back to session.allowedHosts in this case.
      return runSessionHostCheck(trimmed, opts.allowedHosts);
    }
    const host = extractHostname(trimmed);
    if (host && isHostAllowed(host, allowed)) {
      return {
        hostInScope: true,
        hostScopeSource: "structured-scopes",
        hostReason: `host matches HackerOne structured_scopes: [${allowed.join(", ")}]`,
      };
    }
    return {
      hostInScope: false,
      hostScopeSource: "structured-scopes",
      hostReason: `Affected host is not in HackerOne structured_scopes [${allowed.join(", ")}].`,
    };
  }

  return runSessionHostCheck(trimmed, opts.allowedHosts);
}

function runSessionHostCheck(
  affectedUrl: string,
  allowedHosts: string[],
): HostScopeOutcome {
  if (allowedHosts.length === 0) {
    return {
      hostInScope: true,
      hostScopeSource: "none",
      hostReason: "no host-scope configured",
    };
  }

  const host = extractHostname(affectedUrl);
  if (host && isHostAllowed(host, allowedHosts)) {
    return {
      hostInScope: true,
      hostScopeSource: "session-allowed-hosts",
      hostReason: `host matches session allowedHosts: [${allowedHosts.join(", ")}]`,
    };
  }

  return {
    hostInScope: false,
    hostScopeSource: "session-allowed-hosts",
    hostReason: `Affected host is not in allowedHosts [${allowedHosts.join(", ")}].`,
  };
}

function deriveAllowedHostsFromStructuredScopes(
  scopes: StructuredScopeAsset[],
): string[] {
  const hosts: string[] = [];
  for (const s of scopes) {
    if (!s.eligibleForSubmission) continue;
    const type = s.assetType.toUpperCase();
    if (type !== "URL" && type !== "DOMAIN" && type !== "WILDCARD") continue;

    // Normalise `*.example.com` → `example.com`, then strip any trailing path.
    let id = s.assetIdentifier.replace(/^\*\./, "").trim();
    id = id.replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    if (id) hosts.push(id.toLowerCase());
  }
  return hosts;
}

function buildPolicyPrompt(
  report: BountyReport,
  scope: string | null,
  engagement: string | null,
): string {
  const parts: string[] = [
    "# Report",
    `Title: ${report.title}`,
    `Vulnerability class: ${report.vulnerabilityClass}`,
    `Affected URL: ${report.affectedUrl}`,
    `Attacker model: ${report.attackerModel}`,
    `Description: ${report.description}`,
    "",
  ];

  if (scope) {
    parts.push("# scope.md");
    parts.push(scope);
    parts.push("");
  }

  if (engagement) {
    parts.push("# engagement.md");
    parts.push(engagement);
    parts.push("");
  }

  parts.push("Decide whether this report is in scope.");
  return parts.join("\n");
}
