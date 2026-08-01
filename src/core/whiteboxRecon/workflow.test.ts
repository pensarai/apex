import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { newSessionId } from "../id/id";
import type { SessionInfo } from "../session";
import type { ReconAgentRunners, WorkerInput } from "./agents";
import { runWhiteboxReconWithRunners } from "./workflow";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("runWhiteboxRecon", () => {
  it("produces a complete result and reuses content-addressed model results", async () => {
    const fixture = await createFixture();
    const runners = createRunners();

    const first = await runWhiteboxReconWithRunners(
      { codebasePath: fixture.repository, session: fixture.session },
      runners,
    );
    const second = await runWhiteboxReconWithRunners(
      { codebasePath: fixture.repository, session: fixture.session },
      runners,
    );

    expect(first.result.status).toBe("complete");
    expect(first.result.applications).toHaveLength(1);
    expect(first.result.surfaces).toHaveLength(2);
    expect(first.result.surfaces.map((surface) => surface.method)).toEqual([
      "GET",
      "POST",
    ]);
    expect(first.result.surfaces[0]).toEqual(
      expect.objectContaining({
        type: "http",
        path_or_name: "/v1/users/:id",
        source_file: "src/routes.ts",
        source_line: 2,
        handler_file: "src/routes.ts",
        handler_line: 1,
      }),
    );
    expect(first.result.metrics.files_reviewed).toBe(
      first.result.metrics.files_relevant,
    );
    expect(first.result.metrics.candidates_accepted).toBe(
      first.result.metrics.candidates_persisted,
    );
    expect(second.result.applications).toEqual(first.result.applications);
    expect(second.result.surfaces).toEqual(first.result.surfaces);
    expect(second.result.metrics.agent_calls).toBe(0);
    expect(second.result.metrics.bundle_cache_hits).toBe(
      second.result.metrics.shards_total,
    );
    expect(JSON.parse(await readFile(second.artifacts.result, "utf8"))).toEqual(
      second.result,
    );
    expect(runners.plan).toHaveBeenCalledTimes(1);
    expect(runners.analyzeBundle).toHaveBeenCalledTimes(1);
    expect(runners.reconcile).not.toHaveBeenCalled();
  });

  it("returns incomplete without launching map calls when preflight exceeds the call budget", async () => {
    const fixture = await createFixture();
    const runners = createRunners();
    const output = await runWhiteboxReconWithRunners(
      {
        codebasePath: fixture.repository,
        session: fixture.session,
        budget: { maxModelCalls: 1 },
      },
      runners,
    );

    expect(output.result.status).toBe("incomplete");
    expect(output.result.metrics.agent_calls).toBe(1);
    expect(runners.analyzeBundle).not.toHaveBeenCalled();
    expect(output.result.unresolved).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "budget",
          reason: expect.stringContaining("model-call-limit"),
        }),
      ]),
    );
  });

  it("fails preflight before fan-out when the finite candidate queue needs too many bundles", async () => {
    const fixture = await createFixture();
    await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        writeFile(
          path.join(fixture.repository, "src", `route-${index}.ts`),
          `router.get("/route-${index}", handler);\n`,
        ),
      ),
    );
    const runners = createRunners();
    const output = await runWhiteboxReconWithRunners(
      {
        codebasePath: fixture.repository,
        session: fixture.session,
        maxCandidatesPerBundle: 1,
        maxBundles: 4,
      },
      runners,
    );

    expect(output.result.status).toBe("incomplete");
    expect(runners.analyzeBundle).not.toHaveBeenCalled();
    expect(output.result.unresolved).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "budget",
          reason: expect.stringContaining("bundle-count"),
        }),
      ]),
    );
  });

  it("does not persist a candidate with impossible source provenance", async () => {
    const fixture = await createFixture();
    const runners = createRunners({ invalidSourceLine: true });
    const output = await runWhiteboxReconWithRunners(
      { codebasePath: fixture.repository, session: fixture.session },
      runners,
    );

    expect(output.result.status).toBe("incomplete");
    expect(output.result.surfaces).toHaveLength(0);
    expect(output.result.unresolved).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "surface",
          reason: "surface-source-not-in-candidate-evidence",
        }),
        expect.objectContaining({
          kind: "conflict",
          reason: "accepted-candidate-not-persisted",
        }),
      ]),
    );
  });
});

function createRunners(
  options: { invalidSourceLine?: boolean } = {},
): ReconAgentRunners {
  return {
    plan: vi.fn(async () => ({
      result: {
        applications: [
          {
            id: "public-api",
            name: "public-api",
            source_roots: ["."],
            languages: ["TypeScript"],
            frameworks: ["Express"],
            domains: ["api.example.test"],
            disposition: "accepted" as const,
            candidate_ids: [],
          },
        ],
        selectors: [],
        configuration_ownership: [],
        unresolved: [],
      },
      usage: { input_tokens: 100, output_tokens: 20 },
    })),
    analyzeBundle: vi.fn(async ({ bundle, applications }: WorkerInput) => {
      const application = applications[0];
      if (!application) throw new Error("Expected planner application");
      const routeCandidate = bundle.candidates.find(
        (candidate) => candidate.path === "src/routes.ts",
      );
      const reviews = bundle.candidates.map((candidate) => ({
        candidate_id: candidate.id,
        disposition:
          candidate.id === routeCandidate?.id
            ? ("accepted" as const)
            : ("rejected" as const),
        reason:
          candidate.id === routeCandidate?.id
            ? "HTTP registration"
            : "Application metadata already represented by planner",
      }));
      const sourceLine = options.invalidSourceLine ? 999 : 2;
      return {
        result: {
          bundle_id: bundle.id,
          applications: [],
          surfaces: routeCandidate
            ? [
                {
                  candidate_id: routeCandidate.id,
                  application_id: application.id,
                  type: "http" as const,
                  method: "GET",
                  path_or_name: "/v1/users/:id",
                  source_file: "src/routes.ts",
                  source_line: sourceLine,
                  handler_file: "src/routes.ts",
                  handler_line: 1,
                  disposition: "accepted" as const,
                },
                {
                  candidate_id: routeCandidate.id,
                  application_id: application.id,
                  type: "http" as const,
                  method: "POST",
                  path_or_name: "/v1/users/:id",
                  source_file: "src/routes.ts",
                  source_line: sourceLine,
                  handler_file: "src/routes.ts",
                  handler_line: 1,
                  disposition: "accepted" as const,
                },
              ]
            : [],
          resources: [],
          candidate_reviews: reviews,
          unresolved: [],
        },
        usage: { input_tokens: 200, output_tokens: 50 },
      };
    }),
    reconcile: vi.fn(async () => ({
      result: {
        application_merges: [],
        application_updates: [],
        surface_reassignments: [],
        resource_reassignments: [],
        surface_dispositions: [],
        resource_dispositions: [],
        unresolved: [],
      },
      usage: { input_tokens: 50, output_tokens: 10 },
    })),
  };
}

async function createFixture(): Promise<{
  repository: string;
  session: SessionInfo;
}> {
  const root = await mkdtemp(path.join(tmpdir(), "apex-whitebox-workflow-"));
  temporaryDirectories.push(root);
  const repository = path.join(root, "repository");
  const sessionRoot = path.join(root, "session");
  await mkdir(path.join(repository, "src"), { recursive: true });
  await mkdir(sessionRoot, { recursive: true });
  await writeFile(
    path.join(repository, "package.json"),
    '{"name":"fixture","scripts":{"start":"node src/routes.js"},"dependencies":{"express":"latest"}}\n',
  );
  await writeFile(
    path.join(repository, "src", "routes.ts"),
    'const handler = () => {};\nrouter.get("/v1/users/:id", handler);\n',
  );
  const now = Date.now();
  const session: SessionInfo = {
    id: newSessionId(),
    name: "test-whitebox-recon",
    version: "test",
    targets: [repository],
    config: { mode: "operator", agentCwd: repository },
    time: { created: now, updated: now },
    rootPath: sessionRoot,
    logsPath: path.join(sessionRoot, "logs"),
    findingsPath: path.join(sessionRoot, "findings"),
    scratchpadPath: path.join(sessionRoot, "scratchpad"),
    pocsPath: path.join(sessionRoot, "pocs"),
  };
  return { repository, session };
}
