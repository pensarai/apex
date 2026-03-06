import type { PentestReport } from "../schemas";

export function renderJson(report: PentestReport): string {
  return JSON.stringify(report, null, 2);
}
