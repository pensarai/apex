/** Canonical report filenames — use these instead of hardcoding strings. */
export const REPORT_FILENAME_MD = "pentest-report.md";
export const REPORT_FILENAME_JSON = "pentest-report.json";

export type { PentestReport, PentestReportFinding } from "./schemas";

export { buildPentestReport, type ReportContext } from "./builder";

// Renderers
export { renderMarkdown } from "./renderers/markdown";
export { renderJson } from "./renderers/json";
