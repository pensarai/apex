import { stepCountIs } from "ai";
import { AgentRuntime } from "../../agentRuntime";
import { type AgentDefinition, defineAgent } from "../../defineAgent";
import type { SpecializedAgentInput } from "../../offSecAgent";
import { RECON_WORKER_TOOLS } from "../attackSurface/reconToolset";
import { buildReconWorkerPrompt, RECON_WORKER_SYSTEM_PROMPT } from "./prompts";

export interface ReconWorkerInput extends SpecializedAgentInput {
  /** The scoped goal this worker was spawned to pursue. */
  goal: string;
  /** Origin (domain / IP / URL) the goal concerns, when applicable. */
  target?: string;
  /** Cloned-repo path the goal concerns, when applicable. */
  codebasePath?: string;
  /** Tool names to exclude from the default recon-worker roster. */
  excludeTools?: string[];
}

/**
 * A reconnaissance worker: the same primitive toolset as the generalized
 * attack-surface orchestrator, pointed at a single scoped goal. It cannot
 * spawn further recon workers or finalize the run — those tools are
 * orchestrator-only — which bounds the fan-out to one level.
 */
export function reconWorkerDefinition(): AgentDefinition<ReconWorkerInput> {
  return defineAgent<ReconWorkerInput>({
    name: "recon-worker",
    role: "worker",
    system: () => RECON_WORKER_SYSTEM_PROMPT,
    activeTools: (opts) => {
      if (!opts.excludeTools?.length) return [...RECON_WORKER_TOOLS];
      const excluded = new Set(opts.excludeTools);
      return RECON_WORKER_TOOLS.filter((t) => !excluded.has(t));
    },
    target: (opts) => opts.target,
    stopWhen: (opts) => opts.stopWhen ?? stepCountIs(10000),
    prompt: (opts) =>
      buildReconWorkerPrompt(opts.goal, opts.target, opts.codebasePath),
  });
}

export class ReconWorkerAgent extends AgentRuntime<ReconWorkerInput> {
  constructor(opts: ReconWorkerInput) {
    super(reconWorkerDefinition(), opts);
  }
}
