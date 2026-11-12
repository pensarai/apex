import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { hasToolCall, stepCountIs } from "ai";
import { AgentRuntime } from "../../agentRuntime";
import { defineAgent } from "../../defineAgent";
import type { SpecializedAgentInput } from "../../offSecAgent";
import { describeDocumentedTopology } from "../../offSecAgent/tools/documentTopology";
import type { TopologyChangeSet } from "../../offSecAgent/tools/topologyRecords";
import {
  COMPLETION_AUDIT_SYSTEM,
  type CompletionAudit,
  completionAuditSchema,
} from "./completionAudit";
import {
  buildCredentialsBlock,
  buildGeneralizedAttackSurfacePrompt,
  GENERALIZED_ATTACK_SURFACE_SYSTEM_PROMPT,
} from "./generalizedPrompts";
import {
  type ReconCompletionOptions,
  runAuditedRecon,
} from "./reconCompletion";
import { GENERALIZED_ATTACK_SURFACE_TOOLS } from "./reconToolset";
import { finishUpdate, type ReconUpdate, startUpdate } from "./reconUpdate";
import {
  type AttackSurfaceAnalysisResults,
  loadAttackSurfaceResults,
  type PentestTarget,
} from "./types";

export interface GeneralizedAttackSurfaceAgentInput
  extends SpecializedAgentInput {
  /** The primary origin to map — a domain, IP address, or URL. Further origins come from `session.targets`. */
  target: string;
  /**
   * Tool names to drop from the orchestrator roster. A host whose runtime
   * cannot yet back a capability (e.g. durable multi-repo clone or durable
   * recon-worker fan-out) excludes those tools so the agent never calls a tool
   * the environment can't fulfill.
   */
  excludeTools?: string[];
  /**
   * Set when an earlier pass stopped before its report: what is already
   * documented, so this pass continues instead of starting over.
   */
  continuation?: string;
  harness?: "general";
  completion?: ReconCompletionOptions;
  auditPrompt?: string;
  stepLimit?: number;
  /** Re-map from an earlier run's map instead of from scratch. */
  update?: ReconUpdate;
  /** Set by {@link runGeneralizedReconToReport}: the update section of the prompt. */
  updateBrief?: string;
}

/** Typed result returned by {@link GeneralizedAttackSurfaceAgent.consume}. */
export interface GeneralizedAttackSurfaceResult {
  results: AttackSurfaceAnalysisResults | null;
  targets: PentestTarget[];
  resultsPath: string;
  assetsPath: string;
  /** Update runs: what changed relative to the baseline. */
  changeSet?: TopologyChangeSet;
  changesPath?: string;
  /** Update runs the agent did not need to run for, and why. */
  skipped?: string;
  completionAudit?: CompletionAudit;
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
  system: (opts) =>
    opts.auditPrompt
      ? COMPLETION_AUDIT_SYSTEM
      : GENERALIZED_ATTACK_SURFACE_SYSTEM_PROMPT,
  responseSchema: (opts) =>
    opts.auditPrompt ? completionAuditSchema : undefined,
  activeTools: (opts) => {
    if (opts.auditPrompt)
      return ["read_file", "list_files", "grep", "glob", "response"];
    if (!opts.excludeTools?.length)
      return [...GENERALIZED_ATTACK_SURFACE_TOOLS];
    const excluded = new Set(opts.excludeTools);
    return GENERALIZED_ATTACK_SURFACE_TOOLS.filter((t) => !excluded.has(t));
  },
  stopWhen: (opts) => [
    hasToolCall("create_attack_surface_report"),
    stepCountIs(opts.stepLimit ?? 10_000),
  ],
  target: (_opts, state) => state.target,
  prompt: (opts, state) =>
    opts.auditPrompt ??
    buildGeneralizedAttackSurfacePrompt(
      [...new Set([state.target, ...opts.session.targets])],
      opts.session.config?.connectedRepositories ?? [],
      opts.session.config?.prompt,
      opts.continuation,
      opts.updateBrief,
      buildCredentialsBlock(
        (
          opts.credentialManager ?? opts.session.credentialManager
        )?.formatForPrompt(),
        opts.session.config?.authenticationInstructions,
      ),
    ),
  resolveResult: (opts, _state, _stream, validatedResponse) => {
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
    return {
      results,
      targets,
      resultsPath,
      assetsPath,
      ...(opts.auditPrompt
        ? { completionAudit: completionAuditSchema.parse(validatedResponse) }
        : {}),
    };
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
/** Passes allowed after the first when a pass stops before its report. */
export const MAX_RECON_CONTINUATIONS = 3;

/**
 * Run the generalized agent until it writes its report.
 *
 * A model step with no tool call ends a pass, so a model that pauses to think
 * (or returns nothing) would end the run having documented little. The
 * session holds everything documented so far, so a continuation pass is told
 * what exists and what review_topology still flags, and picks up from there.
 * After {@link MAX_RECON_CONTINUATIONS} passes without a report the run fails.
 */
export async function runGeneralizedReconToReport(
  input: GeneralizedAttackSurfaceAgentInput,
  createAgent: (input: GeneralizedAttackSurfaceAgentInput) => {
    consume(): Promise<GeneralizedAttackSurfaceResult>;
    abortAndDrain?(): Promise<void>;
  } = (i) => new GeneralizedAttackSurfaceAgent(i),
): Promise<GeneralizedAttackSurfaceResult> {
  const root = input.session.rootPath;
  let first = input;
  if (input.update) {
    const start = startUpdate(input.update, root);
    if (start.skip && !input.completion)
      return {
        results: null,
        targets: [],
        resultsPath: join(root, "attack-surface-results.json"),
        assetsPath: join(root, "assets"),
        skipped: start.skip,
        ...finishUpdate(input.update, root, input.session.id),
      };
    first = { ...input, updateBrief: start.brief };
  }
  if (input.completion) {
    await input.completion.restore?.();
    const audited = await runAuditedRecon(first, createAgent);
    return input.update
      ? { ...audited, ...finishUpdate(input.update, root, input.session.id) }
      : audited;
  }
  let result = await createAgent(first).consume();
  for (
    let pass = 1;
    !result.results && pass <= MAX_RECON_CONTINUATIONS;
    pass++
  ) {
    result = await createAgent({
      ...first,
      continuation: describeDocumentedTopology(root, pass),
    }).consume();
  }
  if (!result.results)
    throw new Error(
      `Generalized recon for ${input.target} stopped before create_attack_surface_report after ${MAX_RECON_CONTINUATIONS} continuation passes (session ${input.session.id})`,
    );
  return input.update
    ? { ...result, ...finishUpdate(input.update, root, input.session.id) }
    : result;
}

export class GeneralizedAttackSurfaceAgent extends AgentRuntime<
  GeneralizedAttackSurfaceAgentInput,
  GeneralizedAttackSurfaceResult,
  GeneralizedState
> {
  constructor(opts: GeneralizedAttackSurfaceAgentInput) {
    super(generalizedAttackSurfaceDefinition, opts);
  }
}

export { assertCompletionAudit } from "./completionAudit";
