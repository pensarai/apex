import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import type { Finding } from "../agents/offSecAgent";
import {
  buildPentestReport,
  type ReportContext,
  type ReportEngagementContext,
} from "./builder";
import { renderJson } from "./renderers/json";
import { renderMarkdown } from "./renderers/markdown";
import type { PentestReport } from "./schemas";
import { PentestReportChainSchema } from "./schemas";

export const REPORT_FILENAME_MD = "pentest-report.md";
export const REPORT_FILENAME_JSON = "pentest-report.json";

const EngagementReportSourceSchema = z.object({
  coverage: z.array(
    z.object({
      status: z.enum([
        "pending",
        "assigned",
        "running",
        "needs-lead",
        "impact-proven",
        "exhausted",
        "blocked",
      ]),
    }),
  ),
  missions: z
    .object({
      planningStatus: z.enum(["pending", "partial", "complete"]),
      missions: z.array(
        z.object({
          status: z.enum([
            "planned",
            "queued",
            "running",
            "completed",
            "failed",
          ]),
        }),
      ),
    })
    .optional(),
  chains: z.array(PentestReportChainSchema).default([]),
  chainExplore: z.object({
    status: z.enum([
      "pending",
      "running",
      "impact-proven",
      "exhausted",
      "blocked",
    ]),
    summary: z.string().optional(),
    evidence: z.array(z.string()),
  }),
});

export function loadEngagementReportContext(
  sessionRootPath: string,
): ReportEngagementContext | undefined {
  const statePath = join(sessionRootPath, "coordination", "engagement.json");
  if (!existsSync(statePath)) return undefined;
  const parsed = EngagementReportSourceSchema.safeParse(
    JSON.parse(readFileSync(statePath, "utf8")),
  );
  if (!parsed.success) {
    throw new Error(
      `Cannot generate engagement report from ${statePath}: ${parsed.error.message}`,
    );
  }
  return parsed.data;
}

/** Deterministic Phase 3 compiler, reusable after a pentest or engagement run. */
export function writePentestReportArtifacts(input: {
  findings: Finding[];
  context: ReportContext;
  sessionRootPath: string;
}): { report: PentestReport; markdownPath: string; jsonPath: string } {
  const report = buildPentestReport(
    input.findings,
    input.context,
    loadEngagementReportContext(input.sessionRootPath),
  );
  const markdownPath = join(input.sessionRootPath, REPORT_FILENAME_MD);
  const jsonPath = join(input.sessionRootPath, REPORT_FILENAME_JSON);
  writeFileSync(markdownPath, renderMarkdown(report));
  writeFileSync(jsonPath, renderJson(report));
  return { report, markdownPath, jsonPath };
}
