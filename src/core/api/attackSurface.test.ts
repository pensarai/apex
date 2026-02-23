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
    const result = await runAttackSurfaceAgent({
      target: TARGET_URL,
      model: "claude-haiku-4-5",
      session,
    }).result;
    expect(result).toBeDefined();
  });
});
