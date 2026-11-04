export class IncompleteModelStreamError extends Error {
  constructor() {
    super(
      "Model stream ended with unfinished tool input and no provider stop reason",
    );
    this.name = "IncompleteModelStreamError";
  }
}

export function isIncompleteModelStreamError(error: unknown): boolean {
  for (let cause = error, depth = 0; cause != null && depth < 6; depth++) {
    if ((cause as { name?: unknown }).name === "IncompleteModelStreamError")
      return true;
    cause = (cause as { cause?: unknown }).cause;
  }
  return false;
}
