import { describe, expect, it } from "vitest";
import { winScriptFromEnv } from "./__tests__/sandboxScript";
import { winScriptEnv } from "./sandboxScript";

// cmd.exe caps any single environment variable near 8191 characters.
const CMD_ENV_LIMIT = 8191;

describe("winScriptEnv chunking", () => {
  it("keeps every chunk within the cmd.exe env-var budget", () => {
    // ~27KB of base64 — several chunks at the 6000-char bound.
    const script = `# ${"x".repeat(20_000)}\nWrite-Output 'done'\n`;
    const env = winScriptEnv(script);

    const count = Number.parseInt(env.APEX_WIN_SCRIPT_COUNT ?? "0", 10);
    expect(count).toBeGreaterThan(1);
    for (let i = 0; i < count; i++) {
      expect(env[`APEX_WIN_SCRIPT_${i}`]?.length ?? 0).toBeLessThanOrEqual(
        CMD_ENV_LIMIT,
      );
    }
  });

  it("roundtrips through the chunked env exactly", () => {
    const script = [
      "$ErrorActionPreference = 'Stop'",
      "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)",
      "Write-Output 'héllo — Unicode'",
    ].join("\n");
    expect(winScriptFromEnv(winScriptEnv(script))).toBe(script);
  });
});
