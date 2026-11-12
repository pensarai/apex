import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import {
  type GeneralizedAttackSurfaceAgentInput,
  type GeneralizedAttackSurfaceResult,
  MAX_RECON_CONTINUATIONS,
  runGeneralizedReconToReport,
} from "./generalizedAgent";

const reported = {
  results: {},
  targets: [],
} as unknown as GeneralizedAttackSurfaceResult;
const unreported = {
  results: null,
  targets: [],
} as unknown as GeneralizedAttackSurfaceResult;

function makeInput(): GeneralizedAttackSurfaceAgentInput {
  const root = mkdtempSync(join(tmpdir(), "apex-continuation-"));
  mkdirSync(join(root, "topology"));
  writeFileSync(
    join(root, "topology", "component_edge_1.json"),
    JSON.stringify({
      name: "Edge proxy",
      kind: "entrypoint",
      exposure: "public",
    }),
  );
  return {
    target: "http://portal.example",
    session: {
      id: "ses_test",
      rootPath: root,
      targets: ["http://portal.example"],
    } as unknown as SessionInfo,
  } as GeneralizedAttackSurfaceAgentInput;
}

function scripted(results: GeneralizedAttackSurfaceResult[]) {
  const inputs: GeneralizedAttackSurfaceAgentInput[] = [];
  const createAgent = (input: GeneralizedAttackSurfaceAgentInput) => {
    inputs.push(input);
    const next = results[inputs.length - 1] ?? unreported;
    return { consume: async () => next };
  };
  return { inputs, createAgent };
}

describe("runGeneralizedReconToReport", () => {
  it("runs once when the first pass writes its report", async () => {
    const { inputs, createAgent } = scripted([reported]);
    await runGeneralizedReconToReport(makeInput(), createAgent);
    expect(inputs).toHaveLength(1);
    expect(inputs[0]?.continuation).toBeUndefined();
  });

  it("continues from what is documented when a pass stops early", async () => {
    const { inputs, createAgent } = scripted([unreported, reported]);
    const result = await runGeneralizedReconToReport(makeInput(), createAgent);
    expect(result).toBe(reported);
    expect(inputs).toHaveLength(2);
    expect(inputs[1]?.continuation).toContain("Continue (pass 2)");
    expect(inputs[1]?.continuation).toContain("Edge proxy");
    // The documented entry point has no host and no flows; the next pass is told so.
    expect(inputs[1]?.continuation).toContain(
      "public-without-host: Edge proxy",
    );
  });

  it("fails loudly after the last continuation without a report", async () => {
    const { inputs, createAgent } = scripted([]);
    await expect(
      runGeneralizedReconToReport(makeInput(), createAgent),
    ).rejects.toThrow("stopped before create_attack_surface_report");
    expect(inputs).toHaveLength(1 + MAX_RECON_CONTINUATIONS);
  });
});
