import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CredentialManager } from "../../../credentials/manager";
import type { SessionInfo } from "../../../session";
import {
  inProcessSubagentSpawner,
  type SpawnOptions,
  type SubagentSpawner,
} from "../../offSecAgent/subagentSpawner";
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
  targetScopeGaps,
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
  results: { summary: { analysisComplete: true }, targets: [] },
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
  it("does not treat customer ownership or free-form descriptions as test authorization", () => {
    const outside = [
      "https://staging-api.example",
      "ftp://api.example",
      "https://api.example.evil.test",
      "https://api.example@evil.test",
      "https://api.example:8443",
      "https://api.example and its origin URL",
      "sandbox in a test workspace",
      "https://<probe>.callback.example",
    ];
    expect(
      targetScopeGaps({ targets: [{ target: "https://API.example/path" }] }, [
        "https://api.example/",
      ]),
    ).toEqual([]);
    expect(
      targetScopeGaps({ targets: [{ target: "https://api.example/path" }] }, [
        "api.example",
      ]),
    ).toEqual([]);
    expect(
      targetScopeGaps({ targets: [{ target: "api.example" }] }, [
        "https://api.example",
      ]),
    ).toEqual([]);
    for (const target of outside)
      expect(
        targetScopeGaps({ targets: [{ target }] }, ["https://api.example/"]),
      ).toHaveLength(1);
    expect(
      targetScopeGaps({ targets: [{ target: "https://api.example" }] }, []),
    ).toHaveLength(1);
    expect(targetScopeGaps({}, ["https://api.example"])).toEqual([
      "Report does not contain a valid target inventory",
    ]);
  });
  it("rejects out-of-scope targets even when the model approves authorization", async () => {
    const i = input();
    i.completion!.maxPasses = 1;
    const create = factory([]);
    await expect(
      runGeneralizedReconToReport(i, (options) => {
        const agent = create(options);
        return {
          consume: async () => ({
            ...(await agent.consume()),
            results: {
              ...report.results!,
              targets: [
                {
                  target: "https://discovered.example",
                  objective: "Test discovered service",
                  rationale: "Customer-owned",
                },
              ],
            },
          }),
        };
      }),
    ).rejects.toThrow("Recommended target is not a concrete authorized origin");
    const ledger = readCompletionLedger(i.session.rootPath, i.session.id)!;
    expect(ledger.status).toBe("budget-exhausted");
    expect(
      ledger.audit!.assessments.every(
        (item) => item.disposition === "satisfied",
      ),
    ).toBe(true);
  });
  it.each([
    "pass",
    "failure",
    "repair",
  ] as const)("joins read-only audits before global review (%s)", async (outcome) => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    i.completion!.auditConcurrency = 6;
    for (let n = 0; n < 13; n++)
      writeRecord(i.session.rootPath, i.session.id, "component", `cmp_${n}`, {
        id: `cmp_${n}`,
        name: `Service ${n}`,
        evidence: "fixture".repeat(1000),
      });
    let joined = false;
    let batches = 0;
    const batch = vi.fn(
      async (
        requests: readonly SpawnOptions<CompletionAudit>[],
        options: { concurrency: number },
      ) => {
        batches++;
        expect(options.concurrency).toBe(6);
        expect(
          readCompletionLedger(i.session.rootPath, i.session.id)!.audit!
            .assessments,
        ).toEqual([]);
        const prompts = requests.map(({ spec }) => {
          expect(spec.type).toBe("completion-audit");
          if (spec.type !== "completion-audit")
            throw new Error("Wrong child mode");
          return JSON.parse(spec.prompt);
        });
        expect(new Set(prompts.map((p) => p.candidateSnapshot)).size).toBe(1);
        expect(prompts.every((p) => p.priorDispositions.length === 0)).toBe(
          true,
        );
        joined = true;
        return prompts.map((prompt, n) =>
          outcome === "failure" && n === 0
            ? {
                status: "rejected" as const,
                reason: new Error("review unavailable"),
              }
            : {
                status: "fulfilled" as const,
                value:
                  outcome === "repair" && batches === 1 && n === 0
                    ? {
                        assessments: assessment(
                          prompt.requirements,
                        ).assessments.map((item, index) =>
                          index === 0
                            ? {
                                ...item,
                                disposition: "needs-work" as const,
                                rationale: "Missing independent attack path",
                                correctiveAction:
                                  "Inspect the unreviewed write path",
                              }
                            : item,
                        ),
                      }
                    : assessment(prompt.requirements),
              },
        );
      },
    );
    i.subagentSpawner = {
      spawn: vi.fn(),
      spawnMany: vi.fn(),
      spawnBatch: batch as SubagentSpawner["spawnBatch"],
    };
    const create = factory(calls, (_audit, _pass, options) => {
      expect(joined).toBe(true);
      if (outcome === "repair") expect(batches).toBe(2);
      const prompt = JSON.parse(options.auditPrompt!);
      expect(prompt.records).toEqual([]);
      expect(
        prompt.priorDispositions.filter((r: { requirementId: string }) =>
          r.requirementId.startsWith("component:"),
        ),
      ).toHaveLength(13);
    });
    const run = runGeneralizedReconToReport(i, create);
    if (outcome === "failure") {
      await expect(run).rejects.toThrow("Completion audit workers failed");
      const ledger = readCompletionLedger(i.session.rootPath, i.session.id)!;
      expect(ledger.status).toBe("audit-failed");
      expect(ledger.gaps.join(" ")).toContain("review unavailable");
      expect(ledger.audit!.assessments.length).toBeGreaterThan(0);
      expect(calls.some((c) => c.auditPrompt)).toBe(false);
    } else {
      await run;
      expect(
        readCompletionLedger(i.session.rootPath, i.session.id)!.status,
      ).toBe("complete");
    }
    expect(batch).toHaveBeenCalledTimes(outcome === "repair" ? 2 : 1);
    if (outcome === "repair") {
      const work = calls.filter((call) => !call.auditPrompt);
      expect(work).toHaveLength(2);
      expect(work[1]!.continuation).toContain(
        "Inspect the unreviewed write path",
      );
      expect(work[1]!.continuation).toContain("Global review is deferred");
      expect(calls.findIndex((call) => call.auditPrompt)).toBe(2);
    }
  });
  it("keeps connected review ownership stable across restored record order", () => {
    const first = input(),
      second = input();
    const records = [
      ["boundary", { id: "bnd_shared", name: "Shared" }],
      ["component", { id: "cmp_a", name: "A", boundaryId: "bnd_shared" }],
      ["component", { id: "cmp_b", name: "B", boundaryId: "bnd_shared" }],
      [
        "control",
        {
          id: "ctl_shared",
          name: "Shared control",
          appliesToIds: ["bnd_shared"],
        },
      ],
    ] as const;
    for (const [i, record] of records.entries()) {
      const [kind, value] = record;
      for (const [session, order] of [
        [first.session, i],
        [second.session, records.length - i],
      ] as const) {
        const file = writeRecord(
          session.rootPath,
          session.id,
          kind,
          value.id,
          value,
        );
        writeFileSync(
          file,
          JSON.stringify({
            ...value,
            recordedAt: `2026-01-01T00:00:0${order}.000Z`,
            sessionId: session.id,
          }),
        );
      }
    }
    expect(auditRequirements(first.session.rootPath, [], [])).toEqual(
      auditRequirements(second.session.rootPath, [], []),
    );
  });
  it("reviews connected claims together without losing unrelated records", () => {
    const i = input();
    const records = [
      ["boundary", { id: "bnd_app", name: "Application" }],
      ["component", { id: "cmp_api", name: "API", boundaryId: "bnd_app" }],
      [
        "component",
        { id: "cmp_worker", name: "Worker", boundaryId: "bnd_app" },
      ],
      ["flow", { id: "flw_call", fromId: "cmp_api", toId: "cmp_worker" }],
      [
        "threat",
        { id: "thr_tenant", componentId: "cmp_api", title: "Tenant access" },
      ],
      [
        "control",
        {
          id: "ctl_auth",
          name: "Auth",
          appliesToIds: ["flw_call", "cmp_worker"],
        },
      ],
      ["control", { id: "ctl_orphan", name: "Unmapped control" }],
    ] as const;
    for (const [kind, record] of records)
      writeRecord(i.session.rootPath, i.session.id, kind, record.id, record);
    const requirements = auditRequirements(i.session.rootPath, [], []);
    const group = requirements.find((r) => r.id === "component:cmp_api")!;
    expect(group.recordIds!.sort()).toEqual([
      "bnd_app",
      "cmp_api",
      "ctl_auth",
      "flw_call",
      "thr_tenant",
    ]);
    expect(group.description).toContain("supported preconditions");
    expect(group.description).toContain("evidence of enforcement");
    expect(group.description).toContain("tenant binding");
    expect(requirements.map((r) => r.id)).toContain("control:ctl_orphan");
    expect(
      requirements
        .flatMap(
          (r) =>
            r.recordIds ??
            (r.id.includes(":") && !r.id.startsWith("structure:")
              ? [r.id.slice(r.id.indexOf(":") + 1)]
              : []),
        )
        .sort(),
    ).toEqual(records.map(([, r]) => r.id).sort());
  });
  it("keeps a retired member of a connected review in the correction audit", async () => {
    const i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    writeRecord(i.session.rootPath, i.session.id, "component", "api", {
      id: "cmp_api",
      name: "API",
    });
    writeRecord(i.session.rootPath, i.session.id, "threat", "tenant", {
      id: "thr_tenant",
      componentId: "cmp_api",
      title: "Tenant access",
    });
    const create = factory(calls, (audit, pass) => {
      if (pass === 1)
        Object.assign(
          audit.assessments.find(
            (a) => a.requirementId === "component:cmp_api",
          )!,
          {
            disposition: "needs-work",
            rationale: "Unsupported bypass",
            correctiveAction: "Correct the threat",
          },
        );
    });
    await runGeneralizedReconToReport(i, (options) => {
      if (options.continuation?.includes("Unsupported bypass"))
        writeRecord(
          i.session.rootPath,
          i.session.id,
          "threat",
          "tenant-retired",
          {
            id: "thr_tenant",
            componentId: "cmp_api",
            title: "Tenant access",
            status: "retired",
            retiredReason: "Source refutes bypass",
          },
        );
      return create(options);
    });
    const audits = calls
      .filter((call) => call.auditPrompt)
      .map((call) => JSON.parse(call.auditPrompt!));
    expect(audits).toHaveLength(2);
    expect(
      audits[1].requirements.find(
        (r: AuditRequirement) => r.id === "component:cmp_api",
      ).recordIds,
    ).toContain("thr_tenant");
    expect(audits[1].records).toContainEqual(
      expect.objectContaining({ id: "thr_tenant", status: "retired" }),
    );
  });
  it("preserves the update brief when an audited commit changes only prose", async () => {
    const baseline = input(),
      i = input(),
      calls: GeneralizedAttackSurfaceAgentInput[] = [];
    writeRecord(
      baseline.session.rootPath,
      baseline.session.id,
      "component",
      "idp",
      {
        id: "cmp_idp",
        name: "Identity provider",
        kind: "saas",
      },
    );
    i.update = {
      baselineSessionRoot: baseline.session.rootPath,
      trigger: {
        kind: "commit",
        repository: "app",
        range: "before..after",
        changedFiles: ["README.md"],
      },
    };
    await runGeneralizedReconToReport(i, factory(calls));
    expect(calls[0]!.updateBrief).toContain("do not rebuild it");
    expect(calls[0]!.updateBrief).toContain("before..after");
    expect(
      readCompletionLedger(i.session.rootPath, i.session.id)!.objective,
    ).toContain("Rules for an update");
  });
  it("rejects out-of-packet assessments before adding them to the ledger", async () => {
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
    const calls: GeneralizedAttackSurfaceAgentInput[] = [];
    await expect(
      runGeneralizedReconToReport(
        i,
        factory(calls, (audit) => {
          audit.assessments.push({
            ...audit.assessments[0]!,
            requirementId: "objective",
          });
        }),
      ),
    ).rejects.toThrow("out-of-scope assessments: objective");
    expect(calls).toHaveLength(2);
    expect(
      readCompletionLedger(i.session.rootPath, i.session.id),
    ).toMatchObject({
      status: "audit-failed",
      audit: { assessments: [] },
      gaps: [expect.stringContaining("out-of-scope assessments")],
    });
  });
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
