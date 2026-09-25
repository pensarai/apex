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

  if (findings.length === 0 && !report.engagement) {
    return [
      ...header,
      "No findings were identified during this assessment.",
      "",
    ].join("\n");
  }

  const engagementOverview = report.engagement
    ? renderEngagementOverview(report)
    : [];
  const body =
    findings.length > 0
      ? [
          ...(report.engagement ? ["## Detailed findings", ""] : []),
          findings
            .map((finding) => renderFinding(finding, metadata))
            .join("\n"),
        ]
      : [
          "No vulnerability findings were identified during this assessment.",
          "",
        ];

  return [...header, ...engagementOverview, ...body].join("\n");
}

function renderEngagementOverview(report: PentestReport): string[] {
  const engagement = report.engagement;
  if (!engagement) return [];
  const findingsById = new Map(
    report.findings.map((finding) => [finding.id, finding.title]),
  );
  const chains = report.chains ?? [];
  const proven = chains.filter((chain) => chain.status === "impact-proven");
  const exhaustedOrBlocked = chains.filter(
    (chain) => chain.status === "exhausted" || chain.status === "blocked",
  );
  const lines = [
    "## Executive summary",
    "",
    `- **Findings:** ${report.summary.totalFindings} (${formatSeverityCounts(report.summary.bySeverity)})`,
    `- **Missions:** ${engagement.missions.completed}/${engagement.missions.total} completed${engagement.missions.failed ? `; ${engagement.missions.failed} failed` : ""}`,
    `- **Coverage:** ${engagement.coverage.impactProven} impact-proven, ${engagement.coverage.exhausted} exhausted, ${engagement.coverage.blocked} blocked, ${engagement.coverage.open} open (${engagement.coverage.total} total)`,
    `- **Chain-and-explore:** ${engagement.chainExplore.status}${engagement.chainExplore.summary ? ` — ${singleLine(engagement.chainExplore.summary)}` : ""}`,
    "",
  ];

  if (report.findings.length > 0) {
    lines.push(
      "## Findings at a glance",
      "",
      "| Severity | Finding | Endpoint | Practical impact |",
      "| --- | --- | --- | --- |",
      ...report.findings.map(
        (finding) =>
          `| ${finding.severity} | ${tableCell(finding.title)} | ${tableCell(finding.endpoint)} | ${tableCell(firstSentence(finding.impact))} |`,
      ),
      "",
    );
  }

  lines.push("## Proven attack chains", "");
  if (proven.length === 0) {
    lines.push("No proven multi-finding chains were recorded.", "");
  } else {
    for (const chain of proven) {
      lines.push(...renderChain(chain, findingsById));
    }
  }

  lines.push("## Exhausted or blocked chains", "");
  if (exhaustedOrBlocked.length === 0) {
    const terminalSummary = engagement.chainExplore.summary;
    lines.push(
      terminalSummary
        ? `${engagement.chainExplore.status}: ${terminalSummary}`
        : "No exhausted or blocked chain records were produced.",
      "",
    );
  } else {
    for (const chain of exhaustedOrBlocked) {
      lines.push(...renderChain(chain, findingsById));
    }
  }
  return lines;
}

function renderChain(
  chain: NonNullable<PentestReport["chains"]>[number],
  findingsById: Map<string | undefined, string>,
): string[] {
  const linkedFindings = chain.findingIds.map(
    (id) => findingsById.get(id) ?? id,
  );
  return [
    `### ${chain.title}`,
    "",
    `**Status:** ${chain.status}${chain.severity ? `  \n**Severity:** ${chain.severity}` : ""}`,
    "",
    chain.description,
    "",
    `**Impact:** ${chain.impact}`,
    ...(chain.blocker ? ["", `**Blocker:** ${chain.blocker}`] : []),
    ...(linkedFindings.length
      ? ["", `**Linked findings:** ${linkedFindings.join(", ")}`]
      : []),
    ...(chain.steps.length
      ? [
          "",
          "**Chain steps:**",
          "",
          ...chain.steps.flatMap((step, index) => [
            `${index + 1}. **${step.title}:** ${step.description}`,
            ...(step.evidence.length
              ? step.evidence.map((item) => `   - Evidence: ${item}`)
              : []),
          ]),
        ]
      : []),
    ...(chain.evidence.length
      ? ["", "**Evidence:**", "", ...chain.evidence.map((item) => `- ${item}`)]
      : []),
    ...(chain.remediation ? ["", `**Remediation:** ${chain.remediation}`] : []),
    "",
  ];
}

function formatSeverityCounts(
  counts: PentestReport["summary"]["bySeverity"],
): string {
  return `critical ${counts.CRITICAL}, high ${counts.HIGH}, medium ${counts.MEDIUM}, low ${counts.LOW}`;
}

function singleLine(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function firstSentence(value: string): string {
  const normalized = singleLine(value);
  const match = normalized.match(/^.*?[.!?](?:\s|$)/);
  return (match?.[0] ?? normalized).trim();
}

function tableCell(value: string): string {
  return singleLine(value).replaceAll("|", "\\|");
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
