import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  ALL_TOOL_NAMES,
  FAST_STRIKE_EXCLUDED_TOOL_NAMES,
  PLAN_MODE_TOOL_NAMES,
} from "./agents/offSecAgent/tools";

describe("whitebox recon v2 architecture boundary", () => {
  it("exposes only the standard operator orchestration entrypoint", () => {
    expect(ALL_TOOL_NAMES).toContain("run_whitebox_recon");
    expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).toContain("run_whitebox_recon");
    expect(PLAN_MODE_TOOL_NAMES).not.toContain("run_whitebox_recon");
  });

  it("does not import or call the legacy white-box and Surface implementations", async () => {
    const moduleRoot = path.join(process.cwd(), "src", "core", "whiteboxRecon");
    const files = [
      ...(await listTypeScriptFiles(moduleRoot)),
      path.join(
        process.cwd(),
        "src/core/agents/offSecAgent/tools/runWhiteboxRecon.ts",
      ),
      path.join(process.cwd(), "src/core/api/whiteboxRecon.ts"),
      path.join(process.cwd(), "src/core/skills/builtins/whiteboxRecon.ts"),
    ];
    const source = (
      await Promise.all(files.map((file) => readFile(file, "utf8")))
    ).join("\n");
    const forbidden = [
      "@pensar/surface",
      "mapAppWithSurface",
      "runWhiteboxAttackSurfaceWorkflow",
      "WhiteboxAttackSurfaceAgent",
      "document_app",
      "document_endpoint",
      "OffensiveSecurityAgent",
      "read_recon_file",
      "stepCountIs",
      "spawn_pentest_swarm",
      "spawn_coding_agent",
    ];

    for (const token of forbidden) expect(source).not.toContain(token);
  });
});

async function listTypeScriptFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) return listTypeScriptFiles(fullPath);
      return entry.isFile() && entry.name.endsWith(".ts") ? [fullPath] : [];
    }),
  );
  return nested.flat();
}
