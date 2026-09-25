import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  DeploymentPreflightArtifact,
  evaluateDeploymentPrerequisites,
  prepareDeploymentPreflightArtifact,
  sealDeploymentPreflightArtifact,
} from "./engagementPreflight";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "apex-preflight-"));
  directories.push(directory);
  const artifacts = prepareDeploymentPreflightArtifact(directory, {
    contractHash: "contract-hash",
    targetIds: ["target-1", "target-2"],
  });
  return { artifacts, directory };
}

function capability(
  id: string,
  status: "available" | "unavailable" | "unknown",
  targetIds: string[] = [],
) {
  return {
    id,
    kind: "feature" as const,
    label: id,
    status,
    targetIds,
    evidence: status === "unknown" ? [] : [`GET /api/config: ${status}`],
    summary: `Capability is ${status}`,
    observedAt: "2026-09-19T12:00:00.000Z",
  };
}

function requirement(
  id: string,
  targetId: string,
  prerequisiteCapabilityIds: string[],
) {
  return {
    id,
    coverage: [{ targetId, objectiveId: `objective-${id}` }],
    prerequisiteCapabilityIds,
  };
}

describe("deployment preflight artifacts", () => {
  it("creates a resumable draft without replacing existing work", () => {
    const { artifacts, directory } = setup();
    const draft = JSON.parse(readFileSync(artifacts.path, "utf8"));
    expect(draft).toMatchObject({
      version: 1,
      status: "draft",
      contractHash: "contract-hash",
      targetIds: ["target-1", "target-2"],
      capabilities: [],
    });

    writeFileSync(artifacts.path, "{ interrupted", "utf8");
    prepareDeploymentPreflightArtifact(directory, {
      contractHash: "contract-hash",
      targetIds: ["target-1", "target-2"],
    });
    expect(readFileSync(artifacts.path, "utf8")).toBe("{ interrupted");
  });

  it("seals evidence-backed deployment facts", () => {
    const { artifacts } = setup();
    writeFileSync(
      artifacts.path,
      `${JSON.stringify({
        version: 1,
        status: "ready",
        contractHash: artifacts.contractHash,
        targetIds: ["target-1", "target-2"],
        capabilities: [
          capability("llm-provider", "unavailable"),
          capability("verified-user", "available"),
          capability("tts-provider", "unknown"),
        ],
      })}\n`,
      "utf8",
    );

    const sealed = sealDeploymentPreflightArtifact(artifacts);

    expect(sealed.status).toBe("sealed");
    expect(JSON.parse(readFileSync(artifacts.path, "utf8")).status).toBe(
      "sealed",
    );
  });

  it("rejects unavailable facts without evidence", () => {
    expect(() =>
      DeploymentPreflightArtifact.parse({
        version: 1,
        status: "ready",
        contractHash: "contract-hash",
        targetIds: ["target-1"],
        capabilities: [
          {
            ...capability("llm-provider", "unavailable"),
            evidence: [],
          },
        ],
      }),
    ).toThrow("require evidence");
  });

  it("blocks only unavailable prerequisites and preserves unknown work", () => {
    const artifact = DeploymentPreflightArtifact.parse({
      version: 1,
      status: "sealed",
      contractHash: "contract-hash",
      targetIds: ["target-1", "target-2"],
      capabilities: [
        capability("llm-provider", "unavailable"),
        capability("verified-user", "available"),
        capability("tts-provider", "unknown"),
      ],
    });

    const dispositions = evaluateDeploymentPrerequisites(
      [
        requirement("prompt-injection", "target-1", ["llm-provider"]),
        requirement("authorization", "target-1", ["verified-user"]),
        requirement("speech-cache", "target-2", ["tts-provider"]),
      ],
      artifact,
    );

    expect(dispositions).toMatchObject([
      {
        requirementId: "prompt-injection",
        status: "blocked",
        unavailableCapabilityIds: ["llm-provider"],
        evidence: [
          "deployment-preflight:llm-provider:GET /api/config: unavailable",
        ],
      },
      {
        requirementId: "authorization",
        status: "runnable",
      },
      {
        requirementId: "speech-cache",
        status: "unknown",
        unknownCapabilityIds: ["tts-provider"],
      },
    ]);
  });

  it("rejects unknown capability references and target scope mismatches", () => {
    const artifact = DeploymentPreflightArtifact.parse({
      version: 1,
      status: "sealed",
      contractHash: "contract-hash",
      targetIds: ["target-1", "target-2"],
      capabilities: [capability("target-one-user", "available", ["target-1"])],
    });

    expect(() =>
      evaluateDeploymentPrerequisites(
        [requirement("unknown", "target-1", ["missing"])],
        artifact,
      ),
    ).toThrow("unknown deployment capability missing");
    expect(() =>
      evaluateDeploymentPrerequisites(
        [requirement("wrong-scope", "target-2", ["target-one-user"])],
        artifact,
      ),
    ).toThrow("outside requirement wrong-scope scope");
  });

  it("fails if a sealed artifact no longer matches its contract", () => {
    const { artifacts } = setup();
    writeFileSync(
      artifacts.path,
      `${JSON.stringify({
        version: 1,
        status: "ready",
        contractHash: "changed-contract",
        targetIds: ["target-1", "target-2"],
        capabilities: [],
      })}\n`,
      "utf8",
    );

    expect(() => sealDeploymentPreflightArtifact(artifacts)).toThrow(
      "contractHash was changed",
    );
  });
});
