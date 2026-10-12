// Test-only companion to sandboxScript.ts (knip ignores __tests__/
// directories, and vitest runs only *.test.ts — this file is imported by
// tests and never shipped). Reassembles a chunked script from a captured
// env var bag.

export function winScriptFromEnv(
  envVars: Record<string, string> | undefined,
): string {
  const count = Number.parseInt(envVars?.APEX_WIN_SCRIPT_COUNT ?? "0", 10);
  let encoded = "";
  for (let i = 0; i < count; i++)
    encoded += envVars?.[`APEX_WIN_SCRIPT_${i}`] ?? "";
  return Buffer.from(encoded, "base64").toString("utf8");
}
