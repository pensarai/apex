import { runAttackSurfaceAgent } from "./attackSurface";
import { sessions } from "../session";
import { describe, it, expect } from "vitest";

const TARGET_URL = "staging-console.pensar.dev";

describe("Attack Surface", () => {
  it("should be able to get the attack surface", async () => {
    const session = await sessions.create({
      name: "Test Attack Surface",
      targets: [TARGET_URL],
    });
    const { results, targets, resultsPath, assetsPath } =
      await runAttackSurfaceAgent({
        target: TARGET_URL,
        model: "claude-haiku-4-5",
        session,

        callbacks: {
          onToolCall: (d) =>
            console.log(
              `\n→ calling ${d.toolName} \n ${JSON.stringify(d.input, null, 2)}`,
            ),
          onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
          onError: (e) => console.error(e),
        },
      });
    expect(results).toBeDefined();
    expect(targets).toBeDefined();
    expect(resultsPath).toBeDefined();
    expect(assetsPath).toBeDefined();
  });
});
