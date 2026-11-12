import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { loadTopology } from "../../offSecAgent/tools/topologyRecords";
import { auditRecordIndex, buildAuditPackets } from "./auditPackets";
import {
  assertCompletionAudit,
  auditGaps,
  auditRequirements,
  type CompletionAudit,
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
import {
  buildCredentialsBlock,
  buildGeneralizedAttackSurfacePrompt,
} from "./generalizedPrompts";
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
    abortAndDrain?(): Promise<void>;
  },
): Promise<GeneralizedAttackSurfaceResult> {
  const runPass = async (options: GeneralizedAttackSurfaceAgentInput) => {
    const agent = createAgent(options);
    try {
      return await agent.consume();
    } finally {
      await agent.abortAndDrain?.();
    }
  };
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
    buildCredentialsBlock(
      (
        input.credentialManager ?? input.session.credentialManager
      )?.formatForPrompt(),
      input.session.config?.authenticationInstructions,
    ),
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
    const candidate = await runPass({
      ...input,
      harness: "general",
      stepLimit: options.workSteps ?? 200,
      continuation: `Completion ledger (preserve its original objective):\n${JSON.stringify(ledger)}\nContinue from persisted topology. Account for each supplied repository using current source and its revision, or document a concrete access limitation; historical baseline records alone do not establish current coverage. Correct the listed gaps, including inherited omissions even when this began as a drift update. Preserve valid evidence and justified absence, then propose a fresh report.`,
    });
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
      audit: { assessments: [] },
    };
    await persist();
    try {
      const packets = buildAuditPackets(
        ledger.requirements,
        auditInput.topology,
      );
      const writeEvidence = async (name: string, value: unknown) => {
        const relative = `.pensar/completion-audit/${ledger.snapshot}/${name}.json`;
        const content = JSON.stringify(value, null, 2);
        if (input.backends) {
          const written = await input.backends.fs.write(relative, content, {
            mode: "overwrite",
          });
          if (!written.success)
            throw new Error(`Cannot prepare audit evidence: ${written.error}`);
          return written.path;
        }
        const path = join(root, relative);
        mkdirSync(dirname(path), { recursive: true });
        writeFileSync(path, content);
        return path;
      };
      const index = [];
      for (const [number, packet] of packets.entries()) {
        const path = await writeEvidence(`records-${number}`, packet.records);
        index.push(
          ...packet.records.map((record) => ({
            ...auditRecordIndex(record),
            evidenceFile: path,
          })),
        );
      }
      const assessments: CompletionAudit["assessments"] = [];
      for (const [number, packet] of packets.entries()) {
        input.abortSignal?.throwIfAborted();
        const priorReviewsFile = assessments.length
          ? await writeEvidence(`reviews-before-${number}`, assessments)
          : undefined;
        const reviewed = await runPass({
          ...input,
          harness: "general",
          stepLimit: 40,
          auditPrompt: JSON.stringify({
            objective: ledger.objective,
            requirements: packet.requirements,
            previousGaps: ledger.gaps,
            recordIndex: index,
            records:
              Buffer.byteLength(JSON.stringify(packet.records)) <= 48_000
                ? packet.records
                : [],
            priorReviewsFile,
            priorDispositions: assessments.map(
              ({ requirementId, disposition }) => ({
                requirementId,
                disposition,
              }),
            ),
            report: result.results,
            instructions:
              "Review only this packet's requirements. Every record is available unabridged via read_file at its evidenceFile; omitted inline records are not absent evidence. Inspect related records and source as needed. Other packets review the remaining records. Global requirements must reconcile the record index, prior reviews and report against the original inputs, including missing surfaces. Prior reviews are claims to challenge, not proof. Keep each rationale and corrective action concise (at most three sentences each).",
          }),
        });
        if (!reviewed.completionAudit)
          throw new Error(
            `Recon audit ended without a response (session ${sessionId}, packet ${number})`,
          );
        const audit = await checkpoint(
          `audit-${ledger.pass}-${number}`,
          async () => reviewed.completionAudit!,
        );
        assessments.push(...audit.assessments);
        ledger.audit = { assessments: [...assessments] };
        await persist();
      }
    } catch (error) {
      const message =
        error &&
        typeof error === "object" &&
        "message" in error &&
        typeof error.message === "string"
          ? error.message
          : "The model did not produce validated assessments; inspect this session's audit trace.";
      ledger.status = "audit-failed";
      ledger.gaps = [`Audit failed before completion: ${message}`];
      await persist();
      throw error;
    }
    await options.synchronize?.();
    const completionAudit = ledger.audit!;
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
