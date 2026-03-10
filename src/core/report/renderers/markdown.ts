import type { PentestReport, PentestReportFinding } from "../schemas";

export function renderMarkdown(report: PentestReport): string {
  const { metadata, findings, summary } = report;

  const header = [
    `# Pentest Report — ${metadata.target}`,
    "",
    `**Date:** ${metadata.timestamp}  `,
    `**Session:** ${metadata.sessionId}  `,
    `**Model:** ${metadata.model}  `,
    `**Mode:** ${metadata.mode}`,
    "",
    `**Findings:** ${summary.totalFindings}`,
    "",
  ];

  if (findings.length === 0) {
    return [
      ...header,
      "No findings were identified during this assessment.",
      "",
    ].join("\n");
  }

  const body = findings
    .map((finding) => renderFinding(finding, metadata))
    .join("\n");

  return [...header, body].join("\n");
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
    ...(finding.cwes?.length
      ? [
          "## CWE Classification",
          "",
          ...finding.cwes.map((cwe) => `- **${cwe.id}** — ${cwe.reasoning}`),
          "",
        ]
      : []),
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
