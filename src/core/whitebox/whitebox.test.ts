import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../session";
import {
  createWhiteboxCandidate,
  listWhiteboxCandidates,
  pollWhiteboxJob,
  profileCodebase,
  queryWhiteboxCatalog,
  readWhiteboxArtifact,
  readWhiteboxJobLog,
  resolvePathWithinCodebaseRoot,
  resolveSessionWhiteboxArtifactPath,
  selectScanAdaptersWithMeta,
  startWhiteboxJob,
  updateWhiteboxCandidate,
  writeWhiteboxArtifact,
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
  for (let i = 0; i < 40; i++) {
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
  it("detects languages, package managers, manifests, lockfiles, and entry hints", async () => {
    const root = await tempDir("apex-whitebox-profile-");
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ scripts: { build: "tsc", test: "vitest" } }),
    );
    await writeFile(join(root, "package-lock.json"), "{}");
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "src", "routes.ts"), "app.get('/x', handler);");

    const profile = await profileCodebase(root);

    expect(profile.languages).toContain("typescript");
    expect(profile.packageManagers).toContain("npm");
    expect(profile.manifestFiles).toContain("package.json");
    expect(profile.lockfiles).toContain("package-lock.json");
    expect(profile.buildCommands).toContain("npm run build");
    expect(profile.testCommands).toContain("npm run test");
    expect(profile.entryPointHints).toContain("src/routes.ts");
  });
});

describe("whitebox paths", () => {
  it("rejects path escapes outside the codebase root", () => {
    expect(() =>
      resolvePathWithinCodebaseRoot("/tmp/apex-whitebox-root", "../.."),
    ).toThrow(/escapes codebase root/);
  });

  it("only allows whitebox artifact prefixes for session reads", () => {
    expect(() =>
      resolveSessionWhiteboxArtifactPath({
        sessionRootPath: "/session",
        artifactRelativePath: "findings/evil.txt",
      }),
    ).toThrow(/logs\/whitebox/);
  });
});

describe("readWhiteboxArtifact", () => {
  it("round-trips a logs/whitebox artifact", async () => {
    const root = await tempDir("apex-whitebox-artifact-");
    const session = mockSession(root);
    const ref = await writeWhiteboxArtifact({
      session,
      type: "raw-output",
      name: "unit-test",
      content: "hello-whitebox-artifact",
      description: "test",
    });
    const read = await readWhiteboxArtifact({
      session,
      path: ref.path,
    });
    expect(read.content).toContain("hello-whitebox-artifact");
    expect(read.truncated).toBe(false);
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
    ).rejects.toThrow(/artifact|sourceTrace|substantive/);

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
    expect((await listWhiteboxCandidates(session)).length).toBe(1);
  });

  it("allows investigating with substantive sourceTrace only", async () => {
    const root = await tempDir("apex-whitebox-candidates-trace-");
    const session = mockSession(root);
    const candidate = await createWhiteboxCandidate({
      session,
      title: "Trace-only",
      vulnerabilityClass: "xss",
      summary: "sink",
      confidence: "low",
    });
    const updated = await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "investigating",
      sourceTrace: { sink: { file: "src/render.ts", line: 12 } },
    });
    expect(updated.state).toBe("investigating");
  });

  it("rejects illegal state jumps", async () => {
    const root = await tempDir("apex-whitebox-candidates-illegal-");
    const session = mockSession(root);
    const candidate = await createWhiteboxCandidate({
      session,
      title: "Bad jump",
      vulnerabilityClass: "sqli",
      summary: "x",
      confidence: "low",
    });
    await expect(
      updateWhiteboxCandidate({
        session,
        id: candidate.id,
        state: "confirmed",
        verification: { strategy: "n/a", status: "succeeded" },
        artifacts: [
          {
            path: "logs/whitebox/x.txt",
            type: "code-query",
            description: "x",
          },
        ],
      }),
    ).rejects.toThrow(/Illegal whitebox candidate transition/);
  });

  it("requires repro_attempted and succeeded verification for confirmed", async () => {
    const root = await tempDir("apex-whitebox-candidates-confirm-");
    const session = mockSession(root);
    const candidate = await createWhiteboxCandidate({
      session,
      title: "Confirm flow",
      vulnerabilityClass: "idor",
      summary: "x",
      confidence: "high",
    });
    await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "investigating",
      sourceTrace: { notes: "reachable from handler" },
    });
    await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "repro_attempted",
      artifacts: [
        {
          path: "logs/whitebox/repro.txt",
          type: "job-log",
          description: "repro log",
        },
      ],
    });
    const confirmed = await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "confirmed",
      verification: { strategy: "curl PoC", status: "succeeded" },
    });
    expect(confirmed.state).toBe("confirmed");
  });

  it("returns empty list when candidates.json is corrupt", async () => {
    const root = await tempDir("apex-whitebox-candidates-badjson-");
    const session = mockSession(root);
    await mkdir(join(session.scratchpadPath, "whitebox"), { recursive: true });
    await writeFile(
      join(session.scratchpadPath, "whitebox", "candidates.json"),
      "not-json{",
    );
    expect(await listWhiteboxCandidates(session)).toEqual([]);
  });
});

describe("selectScanAdaptersWithMeta", () => {
  it("reports unknown scanner ids separately", async () => {
    const root = await tempDir("apex-whitebox-scanmeta-");
    await writeFile(join(root, "go.mod"), "module x\ngo 1.22\n");
    const profile = await profileCodebase(root);
    const { adapters, unknownScannerIds } = selectScanAdaptersWithMeta({
      profile,
      scannerIds: ["gosec", "definitely-not-a-scanner"],
    });
    expect(unknownScannerIds).toContain("definitely-not-a-scanner");
    expect(adapters.every((a) => a.id !== "definitely-not-a-scanner")).toBe(
      true,
    );
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

  it("marks long-running jobs as timed out", async () => {
    const root = await tempDir("apex-whitebox-job-timeout-");
    const session = mockSession(root);
    const record = startWhiteboxJob({
      session,
      cwd: root,
      command: 'node -e "setTimeout(() => {}, 120000)"',
      timeoutSeconds: 1,
      name: "slow",
    });
    const polled = await waitForJob(record.id);
    expect(polled?.status).toBe("timed_out");
  });
});
