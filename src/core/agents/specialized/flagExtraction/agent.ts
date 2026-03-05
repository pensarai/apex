import { join } from "path";
import { existsSync, mkdirSync, writeFileSync } from "fs";
import { z } from "zod";
import type { SpecializedAgentInput } from "../../offSecAgent/types";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { UnifiedSandbox } from "../../offSecAgent/tools/sandbox";
import { buildTechniquesCatalogPrompt } from "../../../techniques";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FlagExtractionAgentInput extends SpecializedAgentInput {
  /** The base target URL */
  target: string;

  /** Description of the confirmed vulnerability to exploit */
  vulnerabilityDescription: string;

  /** The working attack vector (e.g. "POST to /api/fetch-url with internal URLs") */
  attackVector: string;

  /** Any context gathered so far (internal hostnames, ports, paths, response patterns) */
  context: string;

  /** When set, tools execute inside this sandbox */
  sandbox?: UnifiedSandbox;
}

export interface FlagExtractionResult {
  /** The extracted flag, if found */
  flag: string | null;
  /** Summary of extraction attempts */
  summary: string;
  /** All approaches tried */
  approachesTried: string[];
  /** Step-by-step markdown walkthrough of the attack */
  walkthrough: string;
}

// ---------------------------------------------------------------------------
// Response schema
// ---------------------------------------------------------------------------

const FlagExtractionResponseSchema = z.object({
  flag: z
    .string()
    .nullable()
    .describe(
      "The extracted flag value (e.g. FLAG{...}), or null if not found",
    ),
  summary: z
    .string()
    .describe("Summary of all extraction attempts and results"),
  approachesTried: z
    .array(z.string())
    .describe("List of approaches attempted"),
  walkthrough: z
    .string()
    .describe(
      "A step-by-step markdown walkthrough of the entire attack chain from initial vulnerability to flag extraction (or final failure). " +
        "Include: 1) Vulnerability overview, 2) Each exploitation step with the exact request/command used and the response observed, " +
        "3) Key decision points (why you pivoted or tried a different approach), 4) Final outcome. " +
        "Format as markdown with headers, code blocks for requests/responses, and numbered steps.",
    ),
});

// ---------------------------------------------------------------------------
// FlagExtractionAgent
// ---------------------------------------------------------------------------

export class FlagExtractionAgent extends OffensiveSecurityAgent<FlagExtractionResult> {
  constructor(opts: FlagExtractionAgentInput) {
    const {
      model,
      target,
      vulnerabilityDescription,
      attackVector,
      context,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      sandbox,
    } = opts;

    // Persist agent messages to the execution directory on each step
    const subagentFolder = join(
      session.rootPath,
      "subagents",
      "flag-extraction-agent",
    );

    if (!existsSync(subagentFolder)) {
      mkdirSync(subagentFolder, { recursive: true });
    }

    super({
      system: FLAG_EXTRACTION_SYSTEM_PROMPT,
      prompt: buildPrompt(
        target,
        vulnerabilityDescription,
        attackVector,
        context,
      ),
      model,
      session,
      target,
      authConfig,
      onStepFinish: (e) => {
        onStepFinish?.(e);
        const messages = e.response.messages;
        if (messages !== undefined) {
          writeFileSync(
            join(subagentFolder, "flag-extraction-agent.log"),
            JSON.stringify(messages, null, 2),
          );
        }
      },
      abortSignal,
      sandbox,

      activeTools: [
        "execute_command",
        "http_request",
        "load_technique",
        "response",
      ],

      responseSchema: FlagExtractionResponseSchema,
    });

    // Store for post-run walkthrough writing
    this._subagentFolder = subagentFolder;
    this._target = target;
    this._vulnerabilityDescription = vulnerabilityDescription;
  }

  private _subagentFolder: string;
  private _target: string;
  private _vulnerabilityDescription: string;

  /**
   * Override consume to write the walkthrough markdown after the agent finishes.
   */
  override async consume(
    ...args: Parameters<OffensiveSecurityAgent<FlagExtractionResult>["consume"]>
  ): Promise<FlagExtractionResult> {
    const result = await super.consume(...args);

    // Write the walkthrough markdown to the subagent folder
    if (result?.walkthrough) {
      const walkthroughPath = join(
        this._subagentFolder,
        "flag-extraction-walkthrough.md",
      );
      const header =
        `# Flag Extraction Walkthrough\n\n` +
        `**Target:** ${this._target}\n` +
        `**Vulnerability:** ${this._vulnerabilityDescription}\n` +
        `**Result:** ${result.flag ? `Flag extracted: \`${result.flag}\`` : "Flag not found"}\n` +
        `**Approaches tried:** ${result.approachesTried?.length ?? 0}\n\n---\n\n`;

      writeFileSync(walkthroughPath, header + result.walkthrough);
    }

    return result;
  }
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

const FLAG_EXTRACTION_SYSTEM_PROMPT = `You are a specialized data extraction agent. Your ONLY goal is to extract a flag (format: FLAG{...}) from a target system through a confirmed vulnerability.

You have been given a confirmed vulnerability and working attack vector. Do NOT waste time re-discovering or re-confirming the vulnerability. Go straight to extraction.

Strategy:
1. Start with SERVICE DISCOVERY — discover internal hostnames and services BEFORE brute-forcing paths on a single host
2. Use the provided attack vector to probe for flag data across all discovered hosts
3. Try MANY variations systematically — don't give up after a few attempts
4. Parse ALL responses carefully for flag patterns (FLAG{...}, flag=, secret=, etc.)
5. Think creatively about where flags might be hidden

CRITICAL rules:
- Use execute_command with curl for maximum control over requests (headers, methods, response parsing)
- Always pipe responses through grep -oE 'FLAG\\{[^}]*\\}' to catch flags in large responses
- Use jq to parse JSON responses: jq -r '.flag // .secret // .data // .content' etc.
- Try jq recursive descent: jq -r '.. | strings | select(test("FLAG"))' to find flags buried in nested JSON
- If SSRF: always try fetching through the SSRF endpoint, not directly
- If you get HTML back, check for flags in comments, hidden inputs, data attributes, script tags
- Work fast — try many approaches rather than spending time analyzing individual responses
- When you find the flag, immediately call response with the flag value
- Use the load_technique tool to pull in relevant technique references (e.g. "flag-extraction" for extraction playbooks, "web-hacking" for advanced attack techniques)

${buildTechniquesCatalogPrompt()}`;

function buildPrompt(
  target: string,
  vulnerabilityDescription: string,
  attackVector: string,
  context: string,
): string {
  return `# Flag Extraction Assignment

## Target
${target}

## Confirmed Vulnerability
${vulnerabilityDescription}

## Working Attack Vector
${attackVector}

## Context from Discovery Phase
${context}

## Instructions
Extract the flag (FLAG{...}) from the target using the confirmed vulnerability. Go straight to extraction — the vulnerability has already been confirmed. Try many approaches quickly and parse all responses for flag patterns.`;
}
