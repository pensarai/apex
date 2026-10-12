import { homedir } from "node:os";
import { join, resolve } from "node:path";

export function resolveRunDatabasePath(filename?: string): string {
  return resolve(
    filename ??
      join(
        process.env.PENSAR_DATA_DIR ?? join(homedir(), ".pensar"),
        "runtime",
        "runs.sqlite",
      ),
  );
}
