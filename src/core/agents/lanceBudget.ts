import { z } from "zod";

export const lanceBudgetSchema = z
  .object({
    kind: z.enum(["steps", "tokens", "time"]),
    limit: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  })
  .refine(
    (budget) =>
      budget.kind !== "time" ||
      (budget.limit >= 2 && budget.limit <= 2_147_483_647),
    {
      message: "Time budget must be between 2 and 2147483647 milliseconds",
    },
  );

export type LanceBudget = z.infer<typeof lanceBudgetSchema>;
export const DEFAULT_LANCE_BUDGET: LanceBudget = Object.freeze({
  kind: "steps",
  limit: 200,
});
