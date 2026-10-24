import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { hasToolCall, stepCountIs } from "ai";
import { AgentRuntime } from "../../agentRuntime";
import { defineAgent } from "../../defineAgent";
import type { SpecializedAgentInput } from "../../offSecAgent";
import {
  buildGeneralizedAttackSurfacePrompt,
  GENERALIZED_ATTACK_SURFACE_SYSTEM_PROMPT,
} from "./generalizedPrompts";
import { GENERALIZED_ATTACK_SURFACE_TOOLS } from "./reconToolset";
import {
  type AttackSurfaceAnalysisResults,
  loadAttackSurfaceResults,
  type PentestTarget,
} from "./types";

export interface GeneralizedAttackSurfaceAgentInput
  extends SpecializedAgentInput {
  /** The origin to map — a domain, IP address, or URL. */
  target: string;
  /**
   * Tool names to drop from the orchestrator roster. A host whose runtime
   * cannot yet back a capability (e.g. durable multi-repo clone or durable
   * recon-worker fan-out) excludes those tools so the agent never calls a tool
   * the environment can't fulfill.
   */
  excludeTools?: string[];
}

/** Typed result returned by {@link GeneralizedAttackSurfaceAgent.consume}. */
export interface GeneralizedAttackSurfaceResult {
  results: AttackSurfaceAnalysisResults | null;
  targets: PentestTarget[];
  resultsPath: string;
  assetsPath: string;
}

interface GeneralizedState {
  target: string;
  subagentFolder: string;
}

export const generalizedAttackSurfaceDefinition = defineAgent<
  GeneralizedAttackSurfaceAgentInput,
  GeneralizedAttackSurfaceResult,
  GeneralizedState
>({
  name: "generalized-attack-surface",
  role: "orchestrator",
  createState: (opts) => {
    const subagentFolder = join(
      opts.session.rootPath,
      "subagents",
      "generalized-attack-surface",
    );
    if (!existsSync(subagentFolder)) {
      mkdirSync(subagentFolder, { recursive: true });
    }
    return { target: opts.target, subagentFolder };
  },
  system: () => GENERALIZED_ATTACK_SURFACE_SYSTEM_PROMPT,
  activeTools: (opts) => {
    if (!opts.excludeTools?.length) return [...GENERALIZED_ATTACK_SURFACE_TOOLS];
    const excluded = new Set(opts.excludeTools);
    return GENERALIZED_ATTACK_SURFACE_TOOLS.filter((t) => !excluded.has(t));
  },
  stopWhen: () => [
    hasToolCall("create_attack_surface_report"),
    stepCountIs(10_000),
  ],
  target: (_opts, state) => state.target,
  prompt: (opts, state) =>
    buildGeneralizedAttackSurfacePrompt(
      state.target,
      opts.session.config?.connectedRepositories ?? [],
      opts.session.config?.prompt,
    ),
  resolveResult: (opts) => {
    const resultsPath = join(
      opts.session.rootPath,
      "attack-surface-results.json",
    );
    const assetsPath = join(opts.session.rootPath, "assets");
    let results: AttackSurfaceAnalysisResults | null = null;
    let targets: PentestTarget[] = [];
    if (existsSync(resultsPath)) {
      try {
        results = loadAttackSurfaceResults(resultsPath);
        targets = results.targets || [];
      } catch {
        // Report may not have been written yet.
      }
    }
    return { results, targets, resultsPath, assetsPath };
  },
});

/**
 * The generalized, origin-driven attack-surface agent. Given only an origin
 * (domain / IP / URL), it probes the origin, identifies the services it hosts,
 * maps each to a connected repository where applicable (cloning it to read
 * source), and produces an application-level threat model and pentest
 * objectives — no per-endpoint enumeration. It can fan out scoped recon
 * workers that share its toolset.
 */
export class GeneralizedAttackSurfaceAgent extends AgentRuntime<
  GeneralizedAttackSurfaceAgentInput,
  GeneralizedAttackSurfaceResult,
  GeneralizedState
> {
  constructor(opts: GeneralizedAttackSurfaceAgentInput) {
    super(generalizedAttackSurfaceDefinition, opts);
  }
}
