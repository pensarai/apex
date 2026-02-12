import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import { hasToolCall, stepCountIs } from "ai";
import { join } from "path";
import { existsSync } from "fs";
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import { Session } from "../session";
import { SYSTEM as ATTACK_SURFACE_SYSTEM_PROMPT } from "./legacy/attackSurfaceAgent/prompts";
import { detectOSAndEnhancePrompt } from "./legacy/utils";
import { getScopeDescription } from "./legacy/scope";
import type {
  AttackSurfaceAnalysisResults,
  PentestTarget,
} from "./legacy/attackSurfaceAgent/types";
import { loadAttackSurfaceResults } from "./legacy/attackSurfaceAgent/types";
import { OffensiveSecurityAgent } from "../offensiveAgent/offensiveSecurityAgent";
import type { PersistenceCallbacks } from "../offensiveAgent/tools";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AttackSurfaceAgentInput {
  /** The target to analyze (domain, IP, URL, network range, or org name) */
  target: string;

  /** AI model to drive the agent */
  model: AIModel;

  /** Session that provides paths for assets, logs, etc. */
  session: Session.SessionInfo;

  /** Optional per-provider API key overrides */
  authConfig?: AIAuthConfig;

  /** Optional callback after each agent step */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;

  /** AbortSignal to cancel mid-run */
  abortSignal?: AbortSignal;

  /** Optional persistence callbacks for external storage integration */
  persistence?: PersistenceCallbacks;
}

/** The typed result returned by `AttackSurfaceAgent.consume()`. */
export interface AttackSurfaceResult {
  /** The full analysis results (targets, assets, key findings) */
  results: AttackSurfaceAnalysisResults | null;
  /** All targets identified for deep penetration testing */
  targets: PentestTarget[];
  /** Absolute path to the attack-surface-results.json file */
  resultsPath: string;
  /** Absolute path to the session's assets directory */
  assetsPath: string;
}

// ---------------------------------------------------------------------------
// AttackSurfaceAgent
// ---------------------------------------------------------------------------

/**
 * A recon-focused specialisation of {@link OffensiveSecurityAgent}.
 *
 * Maps the entire attack surface of a target — discovers assets, endpoints,
 * authentication flows, and produces a list of targets for deep testing.
 *
 * `consume()` returns an {@link AttackSurfaceResult} with the full analysis.
 *
 * @example
 * ```ts
 * const agent = new AttackSurfaceAgent({
 *   target: "https://example.com",
 *   model: "claude-sonnet-4-20250514",
 *   session,
 * });
 *
 * const { targets, results } = await agent.consume({
 *   onTextDelta: (d) => process.stdout.write(d.text),
 *   onToolCall:  (d) => console.log(`→ ${d.toolName}`),
 * });
 *
 * console.log(`Identified ${targets.length} targets for deep testing`);
 * ```
 */
export class AttackSurfaceAgent extends OffensiveSecurityAgent<AttackSurfaceResult> {
  constructor(opts: AttackSurfaceAgentInput) {
    const {
      model,
      target,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      persistence,
    } = opts;

    const resultsPath = join(session.rootPath, "attack-surface-results.json");
    const assetsPath = join(session.rootPath, "assets");

    super({
      system: detectOSAndEnhancePrompt(ATTACK_SURFACE_SYSTEM_PROMPT),
      prompt: buildPrompt(target, session),
      model,
      session,
      target,
      authConfig,
      onStepFinish,
      abortSignal,
      persistence,

      activeTools: [
        // Core recon tools
        "execute_command",
        "http_request",
        "document_asset",
        "authenticate_session",
        "delegate_to_auth_subagent",
        "extract_js_endpoints",
        "crawl_authenticated_area",
        "test_endpoint_variations",
        "validate_discovery_completeness",
        "create_attack_surface_report",
        // Browser automation for SPAs, JS-heavy apps, and auth flows
        "browser_navigate",
        "browser_snapshot",
        "browser_screenshot",
        "browser_click",
        "browser_fill",
        "browser_evaluate",
        "browser_console",
        "browser_get_cookies",
      ],

      stopWhen: [
        hasToolCall("create_attack_surface_report"),
        stepCountIs(10000),
      ],
      toolChoice: "auto",

      resolveResult: () => {
        let results: AttackSurfaceAnalysisResults | null = null;
        let targets: PentestTarget[] = [];

        if (existsSync(resultsPath)) {
          try {
            results = loadAttackSurfaceResults(resultsPath);
            targets = results.targets || [];
          } catch {
            // Report may not have been written yet
          }
        }

        return { results, targets, resultsPath, assetsPath };
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Prompt builder
// ---------------------------------------------------------------------------

function buildPrompt(target: string, session: Session.SessionInfo): string {
  const scopeConstraints = session.config?.scopeConstraints;
  const authenticationInstructions = session.config?.authenticationInstructions;
  const scopeDescription = getScopeDescription(scopeConstraints);

  const authBlock = authenticationInstructions
    ? `<authentication_instructions>
${authenticationInstructions}

CRITICAL: When identifying targets for penetration testing, YOU MUST include the authentication information with EVERY target that requires authentication. Parse the above instructions and include them in the authenticationInfo field of each target in your final report.
</authentication_instructions>

`
    : "";

  const scopeRules = scopeConstraints?.strictScope
    ? `
- ONLY test URLs/endpoints within the allowed hosts and ports
- DO NOT perform port scans or subdomain enumeration outside the target
- DO NOT test infrastructure services (databases, caches, etc.)
- Focus ONLY on the web application at the target URL`
    : `
- You may discover and test any related targets
- Prioritize in-scope targets but can explore adjacent services`;

  return `TARGET: ${target}

Session Information:
- Session ID: ${session.id}
- Assets will be saved to: ${join(session.rootPath, "assets")}

${authBlock}SCOPE CONSTRAINTS:
${scopeDescription}

Begin your attack surface analysis by:
1. Understanding the target scope (is it a domain, IP, URL, network range, or organization?)
2. Performing comprehensive reconnaissance to map the attack surface WITHIN SCOPE
3. Identifying assets, services, endpoints, and potential entry points
4. Categorizing discovered targets by type and risk level
5. Document each significant asset using the document_asset tool
6. When complete, call the create_attack_surface_report tool

IMPORTANT SCOPING RULES:
${scopeRules}

Your goal is to provide a comprehensive map of the attack surface, NOT to perform deep exploitation.
Focus on breadth of discovery rather than depth of testing.

Document all discovered assets using the document_asset tool — this creates an inventory of:
- Domains and subdomains (if in scope)
- Web applications and APIs
- Endpoints and routes
- Authentication mechanisms

You MUST provide the final report using create_attack_surface_report tool.`;
}
