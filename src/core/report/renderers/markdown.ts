import type { PentestReport, PentestReportFinding } from "../schemas";

export function renderMarkdown(report: PentestReport): string {
  const { metadata, findings } = report;
  return findings.map((finding) => renderFinding(finding, metadata)).join("\n");
}

function renderFinding(
  finding: PentestReportFinding,
  metadata: PentestReport["metadata"],
): string {
  const lines = [
    `# ${finding.title}`,
    "",
    `**Severity:** ${finding.severity}  `,
    `**Target:** ${metadata.target}  `,
    `**Endpoint:** ${finding.endpoint}  `,
    `**Date:** ${metadata.timestamp}  `,
    `**Session:** ${metadata.sessionId}`,
    "",
    "## Description",
    "",
    finding.description,
    "",
    "## Impact",
    "",
    finding.impact,
    "",
    "## Evidence",
    "",
    "```",
    finding.evidence,
    "```",
    "",
    "## POC",
    "",
    `Path: \`${finding.pocPath}\``,
    "",
    "## Remediation",
    "",
    finding.remediation,
    ...(finding.references
      ? ["", `## References`, "", finding.references]
      : []),
    "",
    "---",
    "",
    "*This finding was automatically documented by the Pensar penetration testing agent.*",
    "",
  ];
  return lines.join("\n");
}
