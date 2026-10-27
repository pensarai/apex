import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createEngagementPlanningTools,
  ENGAGEMENT_PLAN_PATH,
  type EngagementPlan,
  type EngagementTarget,
  engagementManifestHash,
  sealEngagementPlan,
  targetsFromDiscovery,
  targetsFromProvider,
  validateEngagementPlan,
  writeJsonAtomic,
} from "./engagementPlan";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const path = mkdtempSync(join(tmpdir(), "engagement-plan-"));
  roots.push(path);
  return path;
}

const targets: EngagementTarget[] = [
  {
    id: "a",
    target: "https://a.example",
    objectives: [
      { id: "x", text: "Test auth" },
      { id: "y", text: "Test access" },
    ],
  },
  {
    id: "b",
    target: "https://b.example",
    objectives: [{ id: "z", text: "Test upload" }],
  },
];

function plan(
  decisions: EngagementPlan["decisions"],
  missions: EngagementPlan["missions"],
): EngagementPlan {
  return {
    version: 1,
    status: "ready",
    contractHash: engagementManifestHash(targets),
    decisions,
    missions,
  };
}

describe("engagement planning contract", () => {
  it("classifies broad and narrow scopes and covers each included pair once", () => {
    const broad = plan(
      [
        { targetId: "a", scope: "in", reason: "Requested app" },
        { targetId: "b", scope: "in", reason: "Requested app" },
      ],
      [
        {
          id: "m1",
          purpose: "Auth and access",
          assignments: [
            { targetId: "a", objectiveId: "x" },
            { targetId: "a", objectiveId: "y" },
          ],
          dependsOn: [],
        },
        {
          id: "m2",
          purpose: "Upload",
          assignments: [{ targetId: "b", objectiveId: "z" }],
          dependsOn: ["m1"],
        },
      ],
    );
    expect(validateEngagementPlan(broad, targets).missions).toHaveLength(2);
    const narrow = plan(
      [
        { targetId: "a", scope: "in", reason: "Requested app" },
        { targetId: "b", scope: "out", reason: "Excluded by scope" },
      ],
      broad.missions.slice(0, 1),
    );
    expect(validateEngagementPlan(narrow, targets).missions).toHaveLength(1);
    const path = root();
    writeJsonAtomic(join(path, ENGAGEMENT_PLAN_PATH), narrow);
    expect(sealEngagementPlan(path, targets).status).toBe("sealed");
    expect(
      JSON.parse(readFileSync(join(path, ENGAGEMENT_PLAN_PATH), "utf8")).status,
    ).toBe("sealed");
  });

  it("rejects excluded, unknown, duplicated, missing, and cyclic assignments", async () => {
    const decisions: EngagementPlan["decisions"] = [
      { targetId: "a", scope: "in", reason: "Requested" },
      { targetId: "b", scope: "out", reason: "Excluded" },
    ];
    const mission: EngagementPlan["missions"][number] = {
      id: "m1",
      purpose: "Test",
      assignments: [
        { targetId: "a", objectiveId: "x" },
        { targetId: "a", objectiveId: "y" },
      ],
      dependsOn: [],
    };
    const firstPair = { targetId: "a", objectiveId: "x" };
    expect(() =>
      validateEngagementPlan(plan(decisions.slice(0, 1), [mission]), targets),
    ).toThrow("Unclassified");
    expect(() =>
      validateEngagementPlan(
        plan(decisions, [
          { ...mission, assignments: [{ targetId: "b", objectiveId: "z" }] },
        ]),
        targets,
      ),
    ).toThrow("Excluded");
    expect(() =>
      validateEngagementPlan(
        plan(decisions, [
          {
            ...mission,
            assignments: [{ targetId: "missing", objectiveId: "x" }],
          },
        ]),
        targets,
      ),
    ).toThrow("Unknown");
    expect(() =>
      validateEngagementPlan(
        plan(decisions, [
          {
            ...mission,
            assignments: [firstPair, firstPair],
          },
        ]),
        targets,
      ),
    ).toThrow("Duplicate assignment");
    expect(() =>
      validateEngagementPlan(
        plan(decisions, [{ ...mission, assignments: [firstPair] }]),
        targets,
      ),
    ).toThrow("Missing assignment");
    expect(() =>
      validateEngagementPlan(
        plan(decisions, [
          { ...mission, dependsOn: ["m2"] },
          {
            id: "m2",
            purpose: "Other",
            assignments: [{ targetId: "b", objectiveId: "z" }],
            dependsOn: ["m1"],
          },
        ]),
        targets,
      ),
    ).toThrow("Excluded");
    const both = plan(
      decisions.map((decision) => ({ ...decision, scope: "in" as const })),
      [
        { ...mission, dependsOn: ["m2"] },
        {
          id: "m2",
          purpose: "Other",
          assignments: [{ targetId: "b", objectiveId: "z" }],
          dependsOn: ["m1"],
        },
      ],
    );
    expect(() => validateEngagementPlan(both, targets)).toThrow("cycle");
    const planningTools = createEngagementPlanningTools({
      sessionRoot: root(),
      candidates: targets,
    });
    await expect(
      planningTools.write_engagement_plan?.execute?.(
        { plan: plan(decisions, [{ ...mission, assignments: [firstPair] }]) },
        {} as never,
      ),
    ).rejects.toThrow("Missing assignment");
  });

  it("keeps each gRPC target in its own mission", () => {
    const [firstTarget, secondTarget] = targets as [
      EngagementTarget,
      EngagementTarget,
    ];
    const grpcTargets: EngagementTarget[] = [
      {
        ...firstTarget,
        grpc: {
          transport: "grpc",
          serviceFqn: "example.Accounts",
          method: "GetAccount",
        },
      },
      secondTarget,
    ];
    const mixed = plan(
      [
        { targetId: "a", scope: "in", reason: "Requested" },
        { targetId: "b", scope: "in", reason: "Requested" },
      ],
      [
        {
          id: "mixed",
          purpose: "Test both",
          assignments: [
            { targetId: "a", objectiveId: "x" },
            { targetId: "a", objectiveId: "y" },
            { targetId: "b", objectiveId: "z" },
          ],
          dependsOn: [],
        },
      ],
    );
    mixed.contractHash = engagementManifestHash(grpcTargets);
    expect(() => validateEngagementPlan(mixed, grpcTargets)).toThrow(
      "gRPC mission mixed must contain one target",
    );
  });

  it("deduplicates discoveries and host candidate IDs without losing objectives", async () => {
    const discovered = targetsFromDiscovery([
      { target: "https://a.example", objectives: ["Auth"] },
      { target: "https://a.example", objectives: ["Auth", "Access"] },
    ]);
    expect(discovered).toHaveLength(1);
    expect(discovered[0]?.objectives).toHaveLength(2);
    const calls: string[] = [];
    const provided = await targetsFromProvider(["a", "a", "b"], {
      getTarget: async (id) => {
        calls.push(id);
        return targets.find((target) => target.id === id) ?? null;
      },
    });
    expect(calls).toEqual(["a", "b"]);
    expect(provided).toHaveLength(2);
  });

  it("pages long threat model context and rejects unknown target reads", async () => {
    const path = root();
    const calls: Array<[string, number, number]> = [];
    const tools = createEngagementPlanningTools({
      sessionRoot: path,
      candidates: targets,
      provider: {
        getTarget: async () => null,
        readContext: async (id, offset, limit) => {
          calls.push([id, offset, limit]);
          return {
            text: "t".repeat(Math.min(limit, 100 - offset)),
            nextOffset: offset + limit < 100 ? offset + limit : null,
            totalChars: 100,
            version: "v1",
          };
        },
      },
    });
    const execute = tools.read_engagement_context?.execute;
    if (!execute) throw new Error("Context tool is missing");
    const first = await execute(
      { targetId: "a", offset: 0, limit: 40 },
      {} as never,
    );
    const second = await execute(
      { targetId: "a", offset: 40, limit: 60 },
      {} as never,
    );
    expect(first).toMatchObject({ nextOffset: 40 });
    expect(second).toMatchObject({ nextOffset: null });
    expect(calls).toEqual([
      ["a", 0, 40],
      ["a", 40, 60],
    ]);
    await expect(
      execute({ targetId: "unknown", offset: 0, limit: 10 }, {} as never),
    ).rejects.toThrow("Unknown candidate");
    const oversized = createEngagementPlanningTools({
      sessionRoot: path,
      candidates: targets,
      provider: {
        getTarget: async () => null,
        readContext: async () => ({
          text: "x".repeat(20),
          nextOffset: null,
          totalChars: 20,
          version: "v1",
        }),
      },
    });
    await expect(
      oversized.read_engagement_context?.execute?.(
        { targetId: "a", offset: 0, limit: 10 },
        {} as never,
      ),
    ).rejects.toThrow("Invalid context page");
  });
});
