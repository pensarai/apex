import { parseArgs } from "node:util";

export function parseRecordedRunsArgs(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    options: { store: { type: "string" }, spec: { type: "string" } },
  });
  if (
    positionals.length > 1 ||
    (values.spec !== undefined && positionals.length)
  ) {
    throw new Error(
      "Use /runs [runId] [--store <database>] or /runs --spec <file> [--store <database>]",
    );
  }
  return {
    ...(positionals[0] ? { runId: positionals[0] } : {}),
    ...(values.store ? { databasePath: values.store } : {}),
    ...(values.spec ? { specPath: values.spec } : {}),
  };
}
