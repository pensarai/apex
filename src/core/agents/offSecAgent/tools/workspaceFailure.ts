/** Normalize Console API failures into a recovery-oriented agent tool result. */
export function workspaceFailure(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return {
    success: false as const,
    error: message,
    recovery: message.includes("Not authenticated")
      ? "Ask the user to run `/login` in Apex (or the local checkout's `bun src/cli.ts login`), then retry this tool."
      : "Report the API error and do not claim the workspace was updated.",
  };
}
