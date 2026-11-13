import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CredentialManager } from "../../../credentials/manager";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../../offSecAgent/subagentSpawner";
import { readFile } from "../../offSecAgent/tools/readFile";
import type { ReadFileResult } from "../../offSecAgent/tools/readFileImpl";
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
        authenticationInstructions:
          "Verify both tenant administrator and member access.",
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
  it("audits every record in bounded packets before reconciling the whole objective", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    for (let n = 0; n < 30; n++)
      writeRecord(
        i.session.rootPath,
        i.session.id,
        "component",
        `service-${n}`,
        {
          id: `cmp_${n}`,
          name: `Service ${n}`,
          kind: "saas",
          evidence: `source/service-${n}.ts:1`,
        },
      );
    await runGeneralizedReconToReport(i, factory(calls));
    const packets = calls
      .filter((call) => call.auditPrompt)
      .map((call) => JSON.parse(call.auditPrompt!));
    expect(packets.length).toBeGreaterThan(2);
    expect(packets.every((packet) => packet.requirements.length <= 12)).toBe(
      true,
    );
    expect(
      packets.at(-1).requirements.map((r: AuditRequirement) => r.id),
    ).toContain("consistency");
    const ledger = readCompletionLedger(i.session.rootPath, i.session.id)!;
    expect(
      packets
        .flatMap((packet) =>
          packet.requirements.map((r: AuditRequirement) => r.id),
        )
        .sort(),
    ).toEqual(ledger.requirements.map((r) => r.id).sort());
    const record = packets[0].recordIndex.find(
      (r: { id: string }) => r.id === "cmp_29",
    );
    expect(
      JSON.parse(readFileSync(record.evidenceFile, "utf8")),
    ).toContainEqual(
      expect.objectContaining({
        id: "cmp_29",
        evidence: "source/service-29.ts:1",
      }),
    );
    expect(
      JSON.parse(readFileSync(packets.at(-1).priorReviewsFile, "utf8")).filter(
        (review: { requirementId: string }) =>
          review.requirementId.startsWith("component:"),
      ),
    ).toHaveLength(30);
  });
  it("serves omitted long evidence completely through bounded byte reads", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    const evidence = "évidence🔎".repeat(15000) + "critical tail evidence";
    writeRecord(i.session.rootPath, i.session.id, "component", "long", {
      id: "cmp_long",
      name: "Long record",
      kind: "saas",
      evidence,
    });
    await runGeneralizedReconToReport(i, factory(calls));
    const packet = JSON.parse(
      calls.find((call) => call.auditPrompt)!.auditPrompt!,
    );
    expect(packet.records).toEqual([]);
    const record = packet.recordIndex.find(
      (r: { id: string }) => r.id === "cmp_long",
    );
    const reader = readFile({
      subagentSpawner: inProcessSubagentSpawner,
      session: i.session,
      agentCwd: i.session.rootPath,
    });
    let offset = 0,
      content = "";
    while (offset < record.evidenceBytes) {
      const page = (await reader.execute!(
        {
          path: record.evidenceFile,
          byteOffset: offset,
          byteCount: 48000,
          startLine: null,
          endLine: null,
          toolCallDescription: "Read bounded evidence page",
        },
        { toolCallId: "audit-page", messages: [] },
      )) as ReadFileResult;
      expect(page.success).toBe(true);
      expect(page.stoppedAtByte).toBeGreaterThan(offset);
      content += page.content;
      offset = page.stoppedAtByte!;
    }
    expect(JSON.parse(content)[0].evidence).toBe(evidence);
    expect(Buffer.byteLength(content)).toBe(record.evidenceBytes);
  });
  it("does not write a host evidence fallback when a classic sandbox is unavailable", async () => {
    const i = input();
    const execute = vi.fn().mockRejectedValue(new Error("sandbox unavailable"));
    i.sandbox = { type: "linux", execute };
    await expect(runGeneralizedReconToReport(i, factory([]))).rejects.toThrow(
      "sandbox unavailable",
    );
    expect(execute).toHaveBeenCalled();
    expect(
      existsSync(join(i.session.rootPath, ".pensar/completion-audit")),
    ).toBe(false);
    expect(readCompletionLedger(i.session.rootPath, i.session.id)!.status).toBe(
      "audit-failed",
    );
  });
  it("persists earlier packet reviews but cannot certify a partially failed audit", async () => {
    const i = input();
    for (let n = 0; n < 13; n++)
      writeRecord(
        i.session.rootPath,
        i.session.id,
        "boundary",
        `boundary-${n}`,
        {
          id: `bnd_${n}`,
          name: `Boundary ${n}`,
        },
      );
    await expect(
      runGeneralizedReconToReport(
        i,
        factory([], (_audit, packet) => {
          if (packet === 2) throw new Error("second packet unavailable");
        }),
      ),
    ).rejects.toThrow("second packet unavailable");
    const ledger = readCompletionLedger(i.session.rootPath, i.session.id)!;
    expect(ledger.status).toBe("audit-failed");
    expect(ledger.audit!.assessments).toHaveLength(12);
    expect(() =>
      assertCompletionAudit(i.session.rootPath, i.session.id, report.results),
    ).toThrow("missing, unresolved or stale");
  });
  it("reopens work when the final reconciliation contradicts individually accepted records", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    for (let n = 0; n < 13; n++)
      writeRecord(
        i.session.rootPath,
        i.session.id,
        "boundary",
        `boundary-${n}`,
        {
          id: `bnd_${n}`,
          name: `Boundary ${n}`,
        },
      );
    let correctionRequested = false;
    await runGeneralizedReconToReport(
      i,
      factory(calls, (audit) => {
        const consistency = audit.assessments.find(
          (item) => item.requirementId === "consistency",
        );
        if (consistency && !correctionRequested) {
          correctionRequested = true;
          Object.assign(consistency, {
            disposition: "needs-work",
            rationale: "Report contradicts the boundary evidence",
            correctiveAction: "Reconcile the report with the current source",
          });
        }
      }),
    );
    const work = calls.filter((call) => !call.auditPrompt);
    expect(work).toHaveLength(2);
    expect(work[1]!.continuation).toContain(
      "Report contradicts the boundary evidence",
    );
    const reviews = calls
      .filter((call) => call.auditPrompt)
      .flatMap((call) => JSON.parse(call.auditPrompt!).requirements);
    expect(
      reviews.filter((r: AuditRequirement) => r.id === "boundary:bnd_0"),
    ).toHaveLength(2);
    expect(readCompletionLedger(i.session.rootPath, i.session.id)?.status).toBe(
      "complete",
    );
  });
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
    expect(calls[1]!.auditPrompt).toContain(
      "tenant administrator and member access",
    );
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
  it("focuses corrective context on unresolved reviews while retaining the requirement inventory", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    await runGeneralizedReconToReport(
      i,
      factory(calls, (audit, pass) => {
        if (pass !== 1) return;
        Object.assign(audit.assessments[0]!, {
          disposition: "needs-work",
          rationale: "Tenant binding contradicts the component",
          correctiveAction: "Reconcile the control and component",
          evidence: ["unresolved-source-reference"],
        });
        audit.assessments[1]!.evidence = ["already-reviewed-evidence-detail"];
      }),
    );
    const correction = calls[2]!.continuation!;
    expect(correction).toContain("unresolved-source-reference");
    expect(correction).not.toContain("already-reviewed-evidence-detail");
    const prompt = JSON.parse(calls[1]!.auditPrompt!);
    for (const requirement of prompt.requirements)
      expect(correction).toContain(requirement.id);
    expect(prompt).toMatchObject({
      candidatePass: 1,
      packetNumber: 1,
      packetCount: 1,
    });
    expect(prompt.candidateSnapshot).toBeTruthy();
    expect(
      readCompletionLedger(i.session.rootPath, i.session.id)!.requirements,
    ).toHaveLength(prompt.requirements.length);
  });
  it("preserves supplied authentication roles without persisting secrets", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    delete i.session.config!.authenticationInstructions;
    const credentials = new CredentialManager();
    credentials.add({
      id: "cred_admin",
      role: "tenant-admin",
      username: "admin@example.test",
      password: "fixture-secret-never-in-ledger",
    });
    i.credentialManager = credentials;
    await runGeneralizedReconToReport(i, factory(calls));
    const ledger = readCompletionLedger(i.session.rootPath, i.session.id)!;
    expect(ledger.objective).toContain("Map the authenticated surface");
    expect(ledger.objective).toContain("cred_admin");
    expect(calls[1]!.auditPrompt).toContain("tenant-admin");
    expect(JSON.stringify(ledger)).not.toContain(
      "fixture-secret-never-in-ledger",
    );
    credentials.add({ id: "cred_member", role: "member", password: "other" });
    await expect(runGeneralizedReconToReport(i, factory([]))).rejects.toThrow(
      "Recon objective changed during resume",
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
  it("keeps unresolved review requirements when a correction retires a component", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    writeRecord(i.session.rootPath, i.session.id, "component", "provider", {
      id: "cmp_provider",
      name: "Provider",
      kind: "saas",
    });
    await runGeneralizedReconToReport(
      i,
      factory(calls, (audit, pass) => {
        if (pass === 1) {
          Object.assign(audit.assessments[0]!, {
            disposition: "needs-work",
            rationale: "Review the provider",
          });
          writeRecord(
            i.session.rootPath,
            i.session.id,
            "component",
            "retired",
            {
              id: "cmp_provider",
              name: "Provider",
              status: "retired",
              retiredReason: "Duplicate",
            },
          );
        }
      }),
    );
    const secondAudit = JSON.parse(calls[3]!.auditPrompt!);
    expect(secondAudit.requirements).toContainEqual(
      expect.objectContaining({
        id: "component:cmp_provider",
      }),
    );
  });
  it("does not start model work after persistence fails", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    i.completion!.synchronize = async () => {
      throw new Error("record store unavailable");
    };
    await expect(
      runGeneralizedReconToReport(i, factory(calls)),
    ).rejects.toThrow("record store unavailable");
    expect(calls).toHaveLength(0);
  });
  it("cannot complete from a report that explicitly declares incomplete analysis", async () => {
    const i = input();
    await expect(
      runGeneralizedReconToReport(i, (options) => {
        const agent = factory([])(options);
        return {
          consume: async () => {
            const result = await agent.consume();
            return {
              ...result,
              results: {
                ...result.results!,
                summary: {
                  ...result.results!.summary,
                  analysisComplete: false,
                },
              },
            };
          },
        };
      }),
    ).rejects.toMatchObject({ outcome: "budget-exhausted" });
  });
  it("drains each pass before starting another audit or returning completion", async () => {
    const i = input(),
      order: string[] = [];
    const scripted = factory([]);
    await runGeneralizedReconToReport(i, (options) => {
      const name = options.auditPrompt ? "audit" : "work";
      const agent = scripted(options);
      return {
        consume: async () => {
          order.push(`${name}:result`);
          return agent.consume();
        },
        abortAndDrain: async () => {
          await Promise.resolve();
          order.push(`${name}:drained`);
        },
      };
    });
    expect(order).toEqual([
      "work:result",
      "work:drained",
      "audit:result",
      "audit:drained",
    ]);
  });
  it("preserves an incomplete audit without swallowing model failures", async () => {
    const i = input();
    await expect(
      runGeneralizedReconToReport(i, (options) => ({
        consume: async () => {
          if (options.auditPrompt) throw new Error("model response failed");
          return report;
        },
      })),
    ).rejects.toThrow("model response failed");
    expect(
      readCompletionLedger(i.session.rootPath, i.session.id),
    ).toMatchObject({
      status: "audit-failed",
      gaps: ["Audit failed before completion: model response failed"],
    });
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
