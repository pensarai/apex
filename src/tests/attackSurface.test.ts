import { config } from "dotenv";
import { describe, expect, it } from "vitest";
import { runAttackSurfaceAgent } from "../core/api/attackSurface";
import { sessions } from "../core/session";

config();

const TARGET_URL = "staging-console.pensar.dev";

describe.skip("Attack Surface", () => {
  it(
    "should be able to get the attack surface",
    async () => {
      const session = await sessions.create({
        name: "Test Attack Surface",
        targets: [TARGET_URL],
        config: {
          authCredentials: {
            loginUrl: "https://staging-console.pensar.dev/login",
            username: process.env.TEST_AUTH_USERNAME,
            password: process.env.TEST_AUTH_PASSWORD,
          },
        },
      });

      const result = await runAttackSurfaceAgent({
        target: TARGET_URL,
        model: "claude-haiku-4-5",
        session,
      });
      expect(result).toBeDefined();
    },
    { timeout: 300_000 },
  );
});
