import { describe, expect, it } from "vitest";
import { toolExists } from "./utils";

// toolExists is a host-side diagnostic lookup (doctor.ts). Prompt-level
// runtime facts are probed through the agent's command backend and covered
// by src/core/agents/offSecAgent/runtimeContext.test.ts.
describe("toolExists", () => {
  // Windows hosts have no guaranteed /bin/bash for the execSync shell.
  it.skipIf(process.platform === "win32")(
    "finds a POSIX standard tool and rejects a bogus one",
    () => {
      expect(toolExists("sh")).toBe(true);
      expect(toolExists("definitely-not-a-real-tool-xyz")).toBe(false);
    },
  );
});
