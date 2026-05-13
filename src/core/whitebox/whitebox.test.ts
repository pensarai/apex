import { mkdir, mkdtemp, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../session";
import {
  createWhiteboxCandidate,
  listWhiteboxCandidates,
  pollWhiteboxJob,
  profileCodebase,
  queryWhiteboxCatalog,
  readWhiteboxJobLog,
  startWhiteboxJob,
  updateWhiteboxCandidate,
} from "./index";

async function tempDir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

function mockSession(rootPath: string): SessionInfo {
  return {
    id: "ses_test",
    version: "1.0.0",
    targets: [],
    time: { created: Date.now(), updated: Date.now() },
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
    config: {},
  };
}

async function waitForJob(
  id: string,
): Promise<ReturnType<typeof pollWhiteboxJob>> {
  for (let i = 0; i < 20; i++) {
    const record = pollWhiteboxJob(id);
    if (record && record.status !== "running") return record;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return pollWhiteboxJob(id);
}

describe("whitebox catalog", () => {
  it("returns focused sink records without requiring the whole playbook", () => {
    const records = queryWhiteboxCatalog({
      query: "Node SSRF",
      kind: "sink",
      limit: 5,
    });

    expect(records.length).toBeGreaterThan(0);
    expect(records.every((record) => record.kind === "sink")).toBe(true);
  });
});

describe("profileCodebase", () => {
  it("detects languages, package managers, manifests, and entry hints", async () => {
    const root = await tempDir("apex-whitebox-profile-");
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ scripts: { build: "tsc", test: "vitest" } }),
    );
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "src", "routes.ts"), "app.get('/x', handler);");

    const profile = await profileCodebase(root);

    expect(profile.languages).toContain("typescript");
    expect(profile.packageManagers).toContain("npm");
    expect(profile.manifestFiles).toContain("package.json");
    expect(profile.buildCommands).toContain("npm run build");
    expect(profile.testCommands).toContain("npm run test");
    expect(profile.entryPointHints).toContain("src/routes.ts");
  });
});

describe("whitebox candidates", () => {
  it("keeps hypotheses separate from confirmed findings", async () => {
    const root = await tempDir("apex-whitebox-candidates-");
    const session = mockSession(root);

    const candidate = await createWhiteboxCandidate({
      session,
      title: "Potential SSRF",
      vulnerabilityClass: "ssrf",
      summary: "fetch receives user-controlled URL",
      confidence: "medium",
    });

    expect(candidate.state).toBe("hypothesis");
    await expect(
      updateWhiteboxCandidate({
        session,
        id: candidate.id,
        state: "investigating",
      }),
    ).rejects.toThrow(/requires at least one artifact/);

    const updated = await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "investigating",
      artifacts: [
        {
          path: "logs/whitebox/query.txt",
          type: "code-query",
          description: "SSRF sink query",
        },
      ],
    });

    expect(updated.state).toBe("investigating");
    expect(await listWhiteboxCandidates(session)).toHaveLength(1);
  });
});

describe("whitebox jobs", () => {
  it("captures bounded job output in a pollable log", async () => {
    const root = await tempDir("apex-whitebox-job-");
    const session = mockSession(root);
    const record = startWhiteboxJob({
      session,
      cwd: root,
      command: "node -e \"console.log('whitebox-job-ok')\"",
      timeoutSeconds: 5,
      name: "smoke",
    });

    const polled = await waitForJob(record.id);
    const log = readWhiteboxJobLog(record.id);

    expect(polled?.status).toBe("completed");
    expect(log.content).toContain("whitebox-job-ok");
  });
});
