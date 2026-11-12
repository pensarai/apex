import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { writeRecord } from "../../offSecAgent/tools/topologyRecords";
import {
  type AuditRequirement,
  assertCompletionAudit,
  auditGaps,
  auditRequirements,
  type CompletionAudit,
  readCompletionLedger,
  structuralGaps,
} from "./completionAudit";
import {
  type GeneralizedAttackSurfaceAgentInput,
  type GeneralizedAttackSurfaceResult,
  generalizedAttackSurfaceDefinition,
  runGeneralizedReconToReport,
} from "./generalizedAgent";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function input(): GeneralizedAttackSurfaceAgentInput {
  const rootPath = mkdtempSync(join(tmpdir(), "recon-audit-"));
  roots.push(rootPath);
  return {
    target: "https://app.example",
    model: "claude-sonnet-4-5",
    completion: { version: 1, mode: "enforce", maxPasses: 2 },
    session: {
      id: "ses_audit",
      rootPath,
      targets: ["https://app.example"],
      config: {
        prompt: "Review customer SSO and webhook trust. Do not test providers.",
      },
    } as SessionInfo,
  };
}
const report = {
  results: { summary: { analysisComplete: true } },
  targets: [],
  resultsPath: "",
  assetsPath: "",
} as unknown as GeneralizedAttackSurfaceResult;
function assessment(requirements: AuditRequirement[]): CompletionAudit {
  return {
    assessments: requirements.map((r) => ({
      requirementId: r.id,
      disposition: "satisfied",
      rationale: "Checked the fixture source against the requirement",
      evidence: ["fixture/source.ts:1"],
      correctiveAction: "",
    })),
  };
}
function factory(
  calls: GeneralizedAttackSurfaceAgentInput[],
  review?: (
    audit: CompletionAudit,
    pass: number,
    i: GeneralizedAttackSurfaceAgentInput,
  ) => void,
) {
  let pass = 0;
  return (i: GeneralizedAttackSurfaceAgentInput) => ({
    consume: async () => {
      calls.push(i);
      if (!i.auditPrompt) return report;
      const audit = assessment(JSON.parse(i.auditPrompt).requirements);
      review?.(audit, ++pass, i);
      return { ...report, completionAudit: audit };
    },
  });
}
describe("recon completion gate", () => {
  it("requires a read-only audit even when the work pass produces a report", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    await runGeneralizedReconToReport(i, factory(calls));
    expect(calls).toHaveLength(2);
    const tools = generalizedAttackSurfaceDefinition.activeTools(
      calls[1]!,
      {} as never,
    );
    expect(tools).toEqual([
      "read_file",
      "list_files",
      "grep",
      "glob",
      "response",
    ]);
    expect(calls[1]!.auditPrompt).toContain("customer SSO");
    expect(() =>
      assertCompletionAudit(i.session.rootPath, i.session.id, report.results),
    ).not.toThrow();
  });
  it("turns gaps into corrective work and audits the replacement report", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    await runGeneralizedReconToReport(
      i,
      factory(calls, (audit, pass) => {
        if (pass === 1)
          Object.assign(audit.assessments[0]!, {
            disposition: "needs-work",
            rationale: "Missing callback tenant binding",
            correctiveAction: "Inspect callback source",
          });
      }),
    );
    expect(calls).toHaveLength(4);
    expect(calls[2]!.continuation).toContain("Missing callback tenant binding");
    expect(readCompletionLedger(i.session.rootPath, i.session.id)?.pass).toBe(
      2,
    );
  });
  it("rejects self-certification that omits requirements or evidence", () => {
    const required = [
      { id: "a", description: "A" },
      { id: "b", description: "B" },
    ];
    const audit = assessment(required.slice(0, 1));
    audit.assessments[0]!.evidence = [];
    expect(auditGaps(required, audit)).toEqual(
      expect.arrayContaining([
        expect.stringContaining("Missing assessment: b"),
        expect.stringContaining("requires evidence"),
      ]),
    );
    audit.assessments.push({ ...audit.assessments[0]! });
    expect(auditGaps(required, audit).join()).toContain("duplicate");
  });
  it("accepts evidenced absence without manufacturing threats", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    await runGeneralizedReconToReport(
      i,
      factory(calls, (audit) => {
        audit.assessments[0]!.disposition = "justified-absence";
      }),
    );
    expect(readCompletionLedger(i.session.rootPath, i.session.id)?.status).toBe(
      "complete",
    );
  });
  it("stops blocked, preserving partial work and the unresolved requirement", async () => {
    const i = input();
    await expect(
      runGeneralizedReconToReport(
        i,
        factory([], (audit) => {
          Object.assign(audit.assessments[0]!, {
            disposition: "blocked",
            rationale: "Source access missing",
          });
        }),
      ),
    ).rejects.toMatchObject({ outcome: "blocked" });
    expect(
      readCompletionLedger(i.session.rootPath, i.session.id),
    ).toMatchObject({
      status: "blocked",
      gaps: [expect.stringContaining("Source access missing")],
    });
  });
  it("exhausts a bounded correction budget without reporting success", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    await expect(
      runGeneralizedReconToReport(
        i,
        factory(calls, (audit) => {
          audit.assessments = [];
        }),
      ),
    ).rejects.toMatchObject({ outcome: "budget-exhausted" });
    expect(calls).toHaveLength(4);
    expect(readCompletionLedger(i.session.rootPath, i.session.id)?.status).toBe(
      "budget-exhausted",
    );
  });
  it("rejects a stale audit after a late worker writes a component", async () => {
    const i = input();
    await runGeneralizedReconToReport(i, factory([]));
    writeRecord(i.session.rootPath, i.session.id, "component", "late", {
      id: "cmp_late",
      name: "Late provider",
      kind: "saas",
    });
    expect(() =>
      assertCompletionAudit(i.session.rootPath, i.session.id, report.results),
    ).toThrow("stale");
  });
  it("observes gaps without approving an enforced completion", async () => {
    const i = input();
    i.completion!.mode = "observe";
    await runGeneralizedReconToReport(
      i,
      factory([], (audit) => {
        audit.assessments = [];
      }),
    );
    expect(() =>
      assertCompletionAudit(i.session.rootPath, i.session.id, report.results),
    ).toThrow();
  });
  it("inventories provider components and cannot waive dangling references", () => {
    const i = input();
    writeRecord(i.session.rootPath, i.session.id, "component", "idp", {
      id: "cmp_idp",
      name: "Identity provider",
      kind: "identity-provider",
      boundaryId: "missing",
    });
    expect(
      auditRequirements(i.session.rootPath, [], []).map((r) => r.id),
    ).toContain("component:cmp_idp");
    expect(structuralGaps(i.session.rootPath)).toEqual([
      "cmp_idp: boundaryId references missing or retired record missing",
    ]);
  });
  it("replays every model pass using checkpointed decisions", async () => {
    const i = input(),
      saved = new Map<string, unknown>();
    i.completion!.checkpoint = async <T>(
      name: string,
      execute: () => Promise<T>,
    ) => {
      if (!saved.has(name)) saved.set(name, structuredClone(await execute()));
      return structuredClone(saved.get(name)) as T;
    };
    const first: GeneralizedAttackSurfaceAgentInput[] = [],
      second: GeneralizedAttackSurfaceAgentInput[] = [];
    await runGeneralizedReconToReport(
      i,
      factory(first, (audit, pass) => {
        if (pass === 1) audit.assessments = [];
      }),
    );
    await runGeneralizedReconToReport(
      i,
      factory(second, (audit, pass) => {
        if (pass === 1) audit.assessments = [];
      }),
    );
    expect(second.map((c) => c.auditPrompt ?? c.continuation)).toEqual(
      first.map((c) => c.auditPrompt ?? c.continuation),
    );
  });
});
