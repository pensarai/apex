import { captureChunk, captureText, makeCapture } from "./capture";
import type { CommandEvent } from "./types";

export async function collectCommand(
  events: AsyncIterable<CommandEvent>,
  onStdout?: (chunk: string) => void,
) {
  const stdout = makeCapture(1024 * 1024);
  const stderr = makeCapture(1024 * 1024);
  let end: Extract<CommandEvent, { type: "end" }> | undefined;
  for await (const event of events) {
    if (event.type === "stdout") {
      captureChunk(stdout, Buffer.from(event.bytes));
      onStdout?.(event.bytes);
    } else if (event.type === "stderr") {
      captureChunk(stderr, Buffer.from(event.bytes));
    } else if (event.type === "end") end = event;
  }
  if (!end) throw new Error("Command backend ended without an exit status");
  return {
    stdout: captureText(stdout),
    stderr: captureText(stderr),
    exitCode: end.exitCode,
    timedOut: end.timedOut,
    stdoutTruncated: stdout.truncated || end.stdoutTruncated,
    stderrTruncated: stderr.truncated || end.stderrTruncated,
  };
}
