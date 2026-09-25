import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../agents/offSecAgent";
import {
  loadEngagementReportContext,
  writePentestReportArtifacts,
} from "./artifacts";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function makeSessionRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "apex-report-"));
  directories.push(root);
  mkdirSync(join(root, "coordination"), { recursive: true });
  return root;
}

describe("engagement report artifacts", () => {
  it("loads older engagement checkpoints without chain records", () => {
    const root = makeSessionRoot();
    writeFileSync(
      join(root, "coordination", "engagement.json"),
      JSON.stringify({
        coverage: [{ status: "exhausted" }],
        chainExplore: {
          status: "exhausted",
          summary: "No viable escalation chain was found.",
          evidence: [],
        },
      }),
    );

    expect(loadEngagementReportContext(root)).toMatchObject({
      chains: [],
      coverage: [{ status: "exhausted" }],
      chainExplore: { status: "exhausted" },
    });
  });

  it("writes structured JSON and the concise phase-three Markdown", () => {
    const root = makeSessionRoot();
    const timestamp = "2026-09-16T12:00:00.000Z";
    writeFileSync(
      join(root, "coordination", "engagement.json"),
      JSON.stringify({
        coverage: [{ status: "impact-proven" }],
        missions: {
          planningStatus: "complete",
          missions: [{ status: "completed" }],
        },
        chains: [
          {
            id: "chain-1",
            title: "Authenticated user to protected record",
            status: "impact-proven",
            severity: "HIGH",
            description: "A user retrieves another user's record.",
            impact: "Cross-user disclosure.",
            remediation: "Enforce ownership.",
            findingIds: ["finding-1"],
            capabilityIds: [],
            impactProofIds: [],
            objectiveIds: [],
            serviceIds: [],
            targetIds: [],
            evidence: ["finding-1"],
            steps: [],
            createdAt: timestamp,
            updatedAt: timestamp,
          },
        ],
        chainExplore: {
          status: "impact-proven",
          summary: "A material chain was proven.",
          evidence: ["chain-1"],
        },
      }),
    );
    const finding: Finding = {
      id: "finding-1",
      title: "Protected record IDOR",
      severity: "HIGH",
      description: "A user can retrieve a peer record.",
      impact: "Cross-user disclosure.",
      evidence: "HTTP 200",
      endpoint: "/api/records/{id}",
      pocPath: "pocs/idor.sh",
      remediation: "Enforce ownership.",
    };

    const paths = writePentestReportArtifacts({
      findings: [finding],
      context: {
        target: "https://example.test",
        model: "test-model",
        sessionId: "session-1",
        mode: "blackbox",
      },
      sessionRootPath: root,
    });

    const json = JSON.parse(readFileSync(paths.jsonPath, "utf8")) as {
      chains: Array<{ findingIds: string[] }>;
    };
    expect(json.chains[0]?.findingIds).toEqual(["finding-1"]);
    expect(readFileSync(paths.markdownPath, "utf8")).toContain(
      "## Exhausted or blocked chains",
    );
  });
});
