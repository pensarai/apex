import { rmSync } from "node:fs";
import { join } from "node:path";
import { loadTopology } from "../../offSecAgent/tools/topologyRecords";
import {
  assertCompletionAudit,
  auditGaps,
  auditRequirements,
  type CompletionLedger,
  completionSnapshot,
  readCompletionLedger,
  saveCompletionLedger,
  structuralGaps,
} from "./completionAudit";
import type {
  GeneralizedAttackSurfaceAgentInput,
  GeneralizedAttackSurfaceResult,
} from "./generalizedAgent";
import { buildGeneralizedAttackSurfacePrompt } from "./generalizedPrompts";
import { loadAttackSurfaceResults } from "./types";

export interface ReconCompletionOptions {
  version: 1;
  mode: "observe" | "enforce";
  maxPasses?: number;
  /** Durable hosts replay every pass, checkpointing decisions in call order. */
  checkpoint?: <T>(name: string, execute: () => Promise<T>) => Promise<T>;
  workSteps?: number;
  /** Host restores this run after any update baseline has been seeded. */
  restore?: () => Promise<void>;
  /** Drain pending writes and pull worker records before auditing or returning. */
  synchronize?: () => Promise<void>;
}

export class ReconIncompleteError extends Error {
  constructor(
    public readonly outcome: "blocked" | "budget-exhausted",
    public readonly gaps: string[],
  ) {
    super(
      `Recon analysis incomplete: ${outcome}. ${gaps
        .slice(0, 3)
        .map((gap) => gap.slice(0, 300))
        .join("; ")}`,
    );
    this.name = "ReconIncompleteError";
  }
}

export async function runAuditedRecon(
  input: GeneralizedAttackSurfaceAgentInput,
  createAgent: (input: GeneralizedAttackSurfaceAgentInput) => {
    consume(): Promise<GeneralizedAttackSurfaceResult>;
  },
): Promise<GeneralizedAttackSurfaceResult> {
  const options = input.completion;
  if (!options) throw new Error("Recon completion options are required");
  const root = input.session.rootPath;
  const sessionId = input.session.id;
  const origins = [...new Set([input.target, ...input.session.targets])];
  const repositories = input.session.config?.connectedRepositories ?? [];
  const objective = buildGeneralizedAttackSurfacePrompt(
    origins,
    repositories,
    input.session.config?.prompt,
    undefined,
    input.updateBrief,
  );
  const checkpoint =
    options.checkpoint ??
    (async <T>(_name: string, execute: () => Promise<T>) => execute());
  let ledger: CompletionLedger = (!options.checkpoint
    ? readCompletionLedger(root, sessionId)
    : undefined) ?? {
    version: 1,
    revision: 0,
    objective,
    pass: 0,
    status: "working",
    snapshot: "",
    requirements: [],
    audit: null,
    gaps: [],
  };
  if (ledger.objective !== objective)
    throw new Error(
      `Recon objective changed during resume (session ${sessionId})`,
    );
  if (!options.checkpoint && ledger.status === "complete") {
    await options.synchronize?.();
    const resultsPath = join(root, "attack-surface-results.json");
    const results = loadAttackSurfaceResults(resultsPath);
    assertCompletionAudit(root, sessionId, results);
    return {
      results,
      targets: results.targets,
      resultsPath,
      assetsPath: join(root, "assets"),
    };
  }
  const persist = async () => {
    ledger.revision++;
    ledger = await checkpoint(`ledger-${ledger.revision}`, async () => {
      saveCompletionLedger(root, sessionId, ledger);
      await options.synchronize?.();
      return structuredClone(ledger);
    });
  };
  const maxPasses = options.maxPasses ?? 4;
  if (!Number.isInteger(maxPasses) || maxPasses < 1)
    throw new Error("Recon maxPasses must be a positive integer");
  while (ledger.pass < maxPasses) {
    input.abortSignal?.throwIfAborted();
    ledger = { ...ledger, pass: ledger.pass + 1, status: "working" };
    await persist();
    // A report from an earlier pass must never satisfy the next pass's stop condition.
    rmSync(join(root, "attack-surface-results.json"), { force: true });
    const candidate = await createAgent({
      ...input,
      harness: "general",
      stepLimit: options.workSteps ?? 200,
      continuation: `Original objective (preserve every requirement):\n${ledger.objective}\n\nCompletion ledger:\n${JSON.stringify(ledger)}\nContinue from persisted topology. Correct the listed gaps, preserving valid evidence and justified absence, then propose a fresh report.`,
    }).consume();
    await options.synchronize?.();
    const result = await checkpoint(
      `report-${ledger.pass}`,
      async () => candidate,
    );
    if (!result.results) {
      ledger.gaps = [
        "This pass ended without a fresh report; continue from persisted records.",
      ];
      await persist();
      continue;
    }
    const auditInput = await checkpoint(
      `audit-input-${ledger.pass}`,
      async () => ({
        snapshot: completionSnapshot(root, result.results),
        requirements: [
          ...new Map([
            ...ledger.requirements.map(
              (requirement) => [requirement.id, requirement] as const,
            ),
            ...auditRequirements(
              root,
              origins,
              repositories.map((r) => r.name),
            ).map((requirement) => [requirement.id, requirement] as const),
          ]).values(),
        ],
        topology: loadTopology(root),
      }),
    );
    ledger = {
      ...ledger,
      status: "auditing",
      snapshot: auditInput.snapshot,
      requirements: auditInput.requirements,
    };
    await persist();
    const reviewed = await createAgent({
      ...input,
      harness: "general",
      stepLimit: 40,
      auditPrompt: JSON.stringify({
        objective: ledger.objective,
        requirements: ledger.requirements,
        previousGaps: ledger.gaps,
        topology: auditInput.topology,
        report: result.results,
      }),
    }).consume();
    if (!reviewed.completionAudit)
      throw new Error(
        `Recon audit ended without a response (session ${sessionId})`,
      );
    await options.synchronize?.();
    const completionAudit = reviewed.completionAudit;
    const decision = await checkpoint(`decision-${ledger.pass}`, async () => ({
      audit: completionAudit,
      structuralGaps: structuralGaps(root),
      stale: ledger.snapshot !== completionSnapshot(root, result.results),
    }));
    ledger.audit = decision.audit;
    ledger.gaps = [
      ...auditGaps(ledger.requirements, ledger.audit),
      ...decision.structuralGaps,
    ];
    if (!result.results.summary.analysisComplete)
      ledger.gaps.push("Report explicitly declares analysis incomplete");
    if (decision.stale)
      ledger.gaps.push(
        "Topology changed during audit; inspect the current snapshot again",
      );
    if (!ledger.gaps.length) {
      ledger.status = "complete";
      await persist();
      assertCompletionAudit(root, sessionId, result.results);
      return result;
    }
    ledger.status = "correcting";
    await persist();
    if (options.mode === "observe") return result;
    const actionable = ledger.audit.assessments.some(
      (a) => a.disposition === "needs-work",
    );
    if (
      !actionable &&
      ledger.audit.assessments.some((a) => a.disposition === "blocked")
    ) {
      ledger.status = "blocked";
      await persist();
      throw new ReconIncompleteError("blocked", ledger.gaps);
    }
  }
  ledger.status = "budget-exhausted";
  await persist();
  throw new ReconIncompleteError("budget-exhausted", ledger.gaps);
}
