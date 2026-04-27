import { hasToolCall, stepCountIs } from "ai";
import { join } from "path";
import { existsSync, mkdirSync, writeFileSync } from "fs";
import { SYSTEM as ATTACK_SURFACE_SYSTEM_PROMPT } from "./prompts";
import { detectOSAndEnhancePrompt } from "../utils";
import type { AttackSurfaceAnalysisResults, PentestTarget } from "./types";
import { loadAttackSurfaceResults } from "./types";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { SpecializedAgentInput } from "../../offSecAgent/types";
import type { SessionInfo } from "../../../session";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** At least one of `target` or `cwd` must be provided. */
export type AttackSurfaceAgentInput = SpecializedAgentInput &
  (
    | {
        /** The target to analyze (domain, IP, URL, network range, or org name) */
        target: string;
        cwd?: string;
      }
    | {
        target?: string;
        /** Working directory for source-code based analysis */
        cwd: string;
      }
  );

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
export class BlackboxAttackSurfaceAgent extends OffensiveSecurityAgent<AttackSurfaceResult> {
  constructor(opts: AttackSurfaceAgentInput) {
    const {
      model,
      session,
      authConfig,
      onStepFinish,
      onCacheMetrics,
      abortSignal,
      attackSurfaceRegistry,
      eventBus,
      subagentId,
      enableThinking,
    } = opts;
    const target = opts.target ?? opts.cwd!;

    const resultsPath = join(session.rootPath, "attack-surface-results.json");
    const assetsPath = join(session.rootPath, "assets");

    const subagentFolder = join(
      session.rootPath,
      "subagents",
      "attack-surface-agent",
    );

    if (!existsSync(subagentFolder)) {
      mkdirSync(subagentFolder, { recursive: true });
    }

    super({
      system: detectOSAndEnhancePrompt(ATTACK_SURFACE_SYSTEM_PROMPT),
      prompt: buildPrompt(target, session),
      model,
      session,
      target,
      authConfig,
      onStepFinish: (e) => {
        onStepFinish?.(e);
        const messages = e.response.messages;
        if (messages !== undefined) {
          writeFileSync(
            join(subagentFolder, "attack-surface-agent.log"),
            JSON.stringify(messages, null, 2),
          );
        }
      },
      onCacheMetrics,
      abortSignal,
      attackSurfaceRegistry,
      eventBus,
      subagentId,
      enableThinking,
      messages: opts.messages,
      activeTools: [
        // Core recon tools
        "execute_command",
        "document_app",
        "document_endpoint",
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
        // Burp Suite tools (filtered out by base class when Burp is not configured)
        "burp_check_connection",
        "burp_get_proxy_http_history",
        "burp_search_proxy_http_history",
        "burp_get_proxy_websocket_history",
        "burp_get_proxy_intercept_state",
        // Email tools (filtered out by base class when no inboxes configured)
        "email_list_inboxes",
        "email_list_messages",
        "email_search_messages",
        "email_get_message",
        // Web search tools — research target technologies, find known vulnerabilities
        "web_search",
        "get_page",
      ],

      stopWhen: [
        hasToolCall("create_attack_surface_report"),
        stepCountIs(10_000),
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

function buildPrompt(target: string, session: SessionInfo): string {
  const scopeConstraints = session.config?.scopeConstraints;
  const authenticationInstructions = session.config?.authenticationInstructions;
  const enumerateSubdomains = session.config?.enumerateSubdomains ?? false;
  const operatorPrompt = session.config?.prompt;

  const cm = session.credentialManager;
  const credBlock = cm?.formatForPrompt();
  const firstRef = cm?.listReferences()[0];
  const loginTarget = firstRef?.loginUrl ?? target;

  // --- Authentication block ---
  let authBlock: string;

  if (credBlock) {
    const parts: string[] = [];
    if (authenticationInstructions) {
      parts.push(
        `<authentication_instructions>\n${authenticationInstructions}\n</authentication_instructions>`,
      );
    }
    parts.push(credBlock);

    authBlock = `⚠️ AUTHENTICATION CREDENTIALS PROVIDED — YOU MUST LOG IN FIRST.

Your FIRST tool call must be: browser_navigate to ${loginTarget}
Then use browser tools to authenticate. Pass the credentialId to authenticate_session or delegate_to_auth_subagent — secrets are resolved automatically.
For browser_fill on password/secret fields, use credentialId + credentialField instead of raw values.

Do NOT run curl, nmap, dig, or any other command before completing login.
Include authentication information with EVERY target that requires it in your final report.

${parts.join("\n\n")}`;
  } else if (authenticationInstructions) {
    authBlock = `⚠️ AUTHENTICATION INSTRUCTIONS PROVIDED — YOU MUST LOG IN FIRST.

Your FIRST tool call must be: browser_navigate to ${loginTarget}

Do NOT run curl, nmap, dig, or any other command before completing login.
Include authentication information with EVERY target that requires it in your final report.

<authentication_instructions>
${authenticationInstructions}
</authentication_instructions>`;
  } else {
    authBlock = `AUTHENTICATION: No credentials provided. Skip Phase 1 and proceed with unauthenticated discovery.
Note any login pages you find as assets and flag them for pentest agents.`;
  }

  // --- Scope block ---
  const scopeRules = scopeConstraints?.strictScope
    ? `STRICT SCOPE — Only test URLs/endpoints within allowed hosts and ports. Do NOT scan outside the target.`
    : `OPEN SCOPE — You may discover and explore related/adjacent targets.`;

  // --- Subdomain enumeration block ---
  const subdomainBlock = enumerateSubdomains
    ? `SUBDOMAIN ENUMERATION: ENABLED — Execute Phase 2 fully (DNS brute-force, certificate transparency, zone transfers).`
    : `SUBDOMAIN ENUMERATION: DISABLED — Skip Phase 2 entirely. Focus only on the provided target URL.`;

  const startDirective =
    credBlock || authenticationInstructions
      ? `Begin NOW by logging in. Your first tool call must be browser_navigate to ${loginTarget}. After login, continue with the remaining phases.`
      : `Begin attack surface analysis now. Follow the phases defined in your system prompt in order.`;

  const operatorGuidanceBlock = operatorPrompt
    ? `\n## Operator Guidance\n${operatorPrompt}\n`
    : "";

  return `TARGET: ${target}

Session: ${session.id}
Assets directory: ${join(session.rootPath, "assets")}

${authBlock}

SCOPE:
${scopeRules}

${subdomainBlock}
${operatorGuidanceBlock}
${startDirective}`;
}
