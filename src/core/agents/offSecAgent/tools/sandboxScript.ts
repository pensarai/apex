import type { SandboxExecutionResult } from "./sandbox";

// Shared sandbox transport for read/search tools, mirroring the remote file
// mutation conventions: a fixed helper script travels as base64 chunks in
// APEX_WIN_SCRIPT_0..N env vars (6000 chars each — cmd.exe caps any single
// env var near 8191) behind a short static powershell command, and
// paths/parameters travel in env vars rather than being interpolated into
// the command string.

// Chunk bound shared with the remote mutation transport: one chunk must stay
// safely under cmd.exe's 8191-character environment-variable limit.
const WIN_SCRIPT_CHUNK_CHARS = 6000;

// Bootstrap is a fixed short script, so the EncodedCommand stays constant
// and far under cmd.exe's 8191-char limit — no cmd.exe/CRT quoting of the
// payload at all. The (potentially large) helper script still travels as
// base64 chunks in APEX_WIN_SCRIPT_0..N env vars.
const WIN_SCRIPT_BOOTSTRAP = [
  "$s=''",
  "for($i=0;$i -lt [int]$env:APEX_WIN_SCRIPT_COUNT;$i++){$s+=[Environment]::GetEnvironmentVariable('APEX_WIN_SCRIPT_'+$i)}",
  "& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))))",
].join(";");

export const WIN_SCRIPT_COMMAND = `powershell -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(
  WIN_SCRIPT_BOOTSTRAP,
  "utf16le",
).toString("base64")}`;

// UTF-8 console output keeps non-ASCII diagnostics (Unicode paths included)
// decodable by the adapter's text-only stdout capture.
export const WIN_SCRIPT_PRELUDE = [
  "$ErrorActionPreference = 'Stop'",
  "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)",
].join("\n");

export function winScriptEnv(script: string): Record<string, string> {
  const encoded = Buffer.from(script, "utf8").toString("base64");
  const chunks =
    encoded.match(new RegExp(`.{1,${WIN_SCRIPT_CHUNK_CHARS}}`, "g")) ?? [];
  const envVars: Record<string, string> = {
    APEX_WIN_SCRIPT_COUNT: String(chunks.length),
  };
  for (const [i, chunk] of chunks.entries())
    envVars[`APEX_WIN_SCRIPT_${i}`] = chunk;
  return envVars;
}

export const SANDBOX_OP_TIMEOUT_SECONDS = 30;

export function sandboxOpError(
  op: string,
  result: SandboxExecutionResult,
): string {
  const detail = (result.stderr || result.stdout || "unknown error").slice(
    0,
    2_000,
  );
  return `sandbox ${op} failed (exit ${result.exitCode}): ${detail}`;
}
