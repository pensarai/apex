import { z } from "zod";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { SpecializedAgentInput } from "../../offSecAgent/types";
import type { FindingBus } from "../../offSecAgent/findingBus";
import {
  CHAIN_REASONING_SYSTEM_PROMPT,
  buildChainReasoningPrompt,
} from "./prompts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export const ChainObjectiveSchema = z.object({
  target: z.string().describe("The specific URL or target for the follow-up test"),
  objectives: z
    .array(z.string())
    .describe("Testing objectives for the follow-up agent"),
  reasoning: z
    .string()
    .describe("Why this chain is worth pursuing — what evidence supports it"),
  priorFindings: z
    .array(z.string())
    .describe("Titles of findings this chain builds on"),
  requiredInfra: z
    .string()
    .optional()
    .describe(
      "Infrastructure needed: callback_server, malicious_page, payload_host, or null",
    ),
});

export const ChainReasoningResultSchema = z.object({
  chainObjectives: z
    .array(ChainObjectiveSchema)
    .describe("New chain objectives to pursue"),
  analysis: z
    .string()
    .describe("Brief summary of the chain reasoning analysis"),
});

export type ChainObjective = z.infer<typeof ChainObjectiveSchema>;
export type ChainReasoningResult = z.infer<typeof ChainReasoningResultSchema>;

export interface ChainReasoningAgentInput extends SpecializedAgentInput {
  /** Findings from the current round */
  findings: Array<{
    title: string;
    severity: string;
    description: string;
    endpoint: string;
    evidence: string;
  }>;
  /** Optional attack surface summary */
  attackSurfaceSummary?: string;
  /** Optional threat model summary */
  threatModelSummary?: string;
  /** Current recursion depth */
  currentDepth: number;
  /** Maximum recursion depth */
  maxDepth: number;
  /** Shared finding bus for cross-agent discovery */
  findingBus?: FindingBus;
}

// ---------------------------------------------------------------------------
// ChainReasoningAgent
// ---------------------------------------------------------------------------

/**
 * The Chain Reasoning Agent receives findings from a pentest round and
 * reasons about what multi-step attack chains are now possible.
 *
 * It uses the knowledge base for technique inspiration and the shared
 * finding bus for cross-agent discovery. Its output is a set of
 * structured ChainObjective entries that can drive a follow-up swarm.
 */
export class ChainReasoningAgent extends OffensiveSecurityAgent<ChainReasoningResult> {
  constructor(opts: ChainReasoningAgentInput) {
    const {
      model,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      findings,
      attackSurfaceSummary,
      threatModelSummary,
      currentDepth,
      maxDepth,
      findingBus,
    } = opts;

    const activeTools: string[] = [
      "query_attack_knowledge",
      "query_shared_findings",
      "read_file",
      "list_files",
      "response",
    ];

    super({
      system: CHAIN_REASONING_SYSTEM_PROMPT,
      prompt: buildChainReasoningPrompt({
        findings,
        attackSurfaceSummary,
        threatModelSummary,
        currentDepth,
        maxDepth,
      }),
      model,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      activeTools,
      responseSchema: ChainReasoningResultSchema,

      // Inject FindingBus via extraTools context
      // The querySharedFindings tool will receive the bus via the extended ToolContext
      extraTools: {},
    });
  }
}
