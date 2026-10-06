export interface TuiOptions {
  sessionId?: string;
  modelId?: string;
}

export function parseTuiArgs(args: readonly string[]): TuiOptions {
  if (args.length === 0) return {};
  if (args[0] !== "--resume") {
    throw new Error("Use pensar --resume <session-id> [--model <model>].");
  }

  const sessionId = args[1];
  if (!sessionId || !/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(sessionId)) {
    throw new Error("--resume requires a saved session ID.");
  }
  if (args.length === 2) return { sessionId };

  const modelId = args[3];
  if (
    args.length !== 4 ||
    args[2] !== "--model" ||
    !modelId?.trim() ||
    modelId.startsWith("-")
  ) {
    throw new Error("Use pensar --resume <session-id> [--model <model>].");
  }
  return { sessionId, modelId };
}
