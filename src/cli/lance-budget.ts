import type { LanceOptions } from "../core/agents/lance";
import { lanceBudgetSchema } from "../core/agents/lanceBudget";

export function parseLanceBudget(args: string[]): LanceOptions {
  const values = new Map<string, number>();
  for (const flag of [
    "--max-steps",
    "--max-tokens",
    "--timeout-ms",
    "--deadline-at",
  ]) {
    const index = args.indexOf(flag);
    if (index === -1) continue;
    const raw = args[index + 1];
    if (
      !raw ||
      !/^\d+$/.test(raw) ||
      !Number.isSafeInteger(Number(raw)) ||
      Number(raw) <= 0
    )
      throw new Error(`${flag} requires a positive safe integer`);
    if (args.indexOf(flag, index + 1) !== -1)
      throw new Error(`Duplicate ${flag}`);
    values.set(flag, Number(raw));
  }
  if (values.size && !args.includes("--lance"))
    throw new Error("Lance budget flags require --lance");
  const steps = values.get("--max-steps");
  const tokens = values.get("--max-tokens");
  const timeoutMs = values.get("--timeout-ms");
  const deadlineAt = values.get("--deadline-at");
  if (
    Number(steps !== undefined) +
      Number(tokens !== undefined) +
      Number(timeoutMs !== undefined || deadlineAt !== undefined) >
    1
  )
    throw new Error(
      "Choose one Lance budget: --max-steps, --max-tokens, or --timeout-ms/--deadline-at",
    );
  if (steps !== undefined || tokens !== undefined)
    return {
      budget: lanceBudgetSchema.parse({
        kind: steps !== undefined ? "steps" : "tokens",
        limit: steps ?? tokens,
      }),
    };
  if (timeoutMs !== undefined)
    lanceBudgetSchema.parse({ kind: "time", limit: timeoutMs });
  if (deadlineAt !== undefined)
    lanceBudgetSchema.parse({ kind: "time", limit: deadlineAt - Date.now() });
  return {
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    ...(deadlineAt !== undefined ? { deadlineAt } : {}),
  };
}
