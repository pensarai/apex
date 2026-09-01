import type { AttackPath } from "../../../lib/attack-path/types";
import { hasCanonicalName } from "../../../lib/cwe/types";
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
    ...(finding.attackPath?.length
      ? [
          "## Attack Path",
          "",
          ...finding.attackPath.map(renderAttackPathHop),
          "",
        ]
      : []),
    "## Evidence",
    "",
    "```",
    finding.evidence,
    "```",
    "",
    ...(finding.evidenceFiles?.length
      ? [
          "## Evidence Files",
          "",
          ...finding.evidenceFiles.map(
            (ef) => `- **[${ef.type}]** \`${ef.path}\` — ${ef.description}`,
          ),
          "",
        ]
      : []),
    ...(finding.cwes?.length
      ? [
          "## CWE Classification",
          "",
          ...finding.cwes.map(
            (cwe) =>
              `- **${cwe.id}**${hasCanonicalName(cwe) ? `: ${cwe.name}` : ""} — ${cwe.reasoning}`,
          ),
          "",
        ]
      : []),
    ...(finding.rootCauseGroup
      ? [
          "## Root Cause Group",
          "",
          `**Group:** \`${finding.rootCauseGroup}\``,
          ...(finding.relatedFindings?.length
            ? [
                "",
                "**Related Findings:**",
                ...finding.relatedFindings.map((rf) => `- ${rf}`),
              ]
            : []),
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

function renderAttackPathHop(hop: AttackPath[number], index: number): string {
  const parts: string[] = [];
  if (hop.applicationName) parts.push(`**${hop.applicationName}**`);
  if (hop.applicationId) parts.push(`(\`${hop.applicationId}\`)`);
  if (hop.host) parts.push(`host \`${hop.host}\``);
  if (hop.relationshipType) parts.push(`via ${hop.relationshipType}`);
  if (hop.notes) parts.push(`— ${hop.notes}`);
  return `${index + 1}. ${parts.join(" ") || "Unspecified system member"}`;
}
