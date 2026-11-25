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

  if (report.coverage) {
    const { status, targets } = report.coverage;
    const count = (value: "completed" | "failed" | "untested") =>
      targets.filter((target) => target.status === value).length;
    header.push(
      "## Worker Coverage",
      "",
      `**Worker coverage:** ${status === "complete" ? "Complete" : "Incomplete"}`,
      "",
      `${count("completed")} completed, ${count("failed")} failed, ${count("untested")} untested (of ${targets.length} scheduled targets).`,
      "",
      "This records scheduled worker completion, not completion of every security check or objective.",
      "",
    );
    if (status === "incomplete") {
      header.push(
        "**Testing is incomplete. Findings only reflect the work performed; missing findings do not establish that the target is secure.**",
        "",
      );
    }
    if (targets.length === 0) {
      header.push("No targets were scheduled for testing.", "");
    }
    for (const outcome of targets) {
      header.push(
        `- **${outcome.status}** — ${outcome.target}`,
        ...outcome.objectives.map((objective) => `  - ${objective}`),
      );
    }
    header.push("");
  }

  if (findings.length === 0) {
    return [
      ...header,
      report.coverage?.status === "incomplete"
        ? "No findings were identified in the work completed. Assessment coverage is incomplete."
        : "No findings were identified during this assessment.",
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
