import { describe, expect, it } from "vitest";
import type { ToolSet } from "ai";
import { restrictToolsToActive } from "./toolGating";

const fakeTool = (name: string) => ({ description: name }) as unknown;
const toolset = (...names: string[]): ToolSet =>
  Object.fromEntries(names.map((n) => [n, fakeTool(n)])) as ToolSet;

describe("restrictToolsToActive", () => {
  it("drops registry tools the model was never shown so hallucinated names cannot execute", () => {
    const tools = toolset(
      "list_repositories",
      "read_file",
      "execute_command",
      "spawn_pentest_swarm",
    );
    const result = restrictToolsToActive(tools, ["list_repositories", "read_file"]);
    expect(Object.keys(result).sort()).toEqual(["list_repositories", "read_file"]);
    expect(result).not.toHaveProperty("execute_command");
    expect(result).not.toHaveProperty("spawn_pentest_swarm");
  });

  it("keeps only the intersection when the allowlist names an absent tool", () => {
    const result = restrictToolsToActive(toolset("a", "b"), ["a", "missing"]);
    expect(Object.keys(result)).toEqual(["a"]);
  });

  it("returns an empty map for an empty allowlist", () => {
    expect(restrictToolsToActive(toolset("a", "b"), [])).toEqual({});
  });
});
