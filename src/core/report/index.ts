/** Canonical report filenames — use these instead of hardcoding strings. */
export const REPORT_FILENAME_MD = "pentest-report.md";
export const REPORT_FILENAME_JSON = "pentest-report.json";

export { buildPentestReport, type ReportContext } from "./builder";
export { renderJson } from "./renderers/json";

// Renderers
export { renderMarkdown } from "./renderers/markdown";
export {
  type PentestReport,
  type PentestReportFinding,
} from "./schemas";
