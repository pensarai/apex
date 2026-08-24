import { mkdir, writeFile } from "fs/promises";
import { join } from "path";
import type { TriageResult } from "./types";

export interface WriteOutputsInput {
  result: TriageResult;
  outputDir: string;
}

export interface WriteOutputsResult {
  triageMarkdownPath: string;
  decisionJsonPath: string;
}

export async function writeTriageOutputs(
  input: WriteOutputsInput,
): Promise<WriteOutputsResult> {
  await mkdir(input.outputDir, { recursive: true });

  const triageMarkdownPath = join(input.outputDir, "triage.md");
  const decisionJsonPath = join(input.outputDir, "decision.json");

  await Promise.all([
    writeFile(triageMarkdownPath, renderTriageMarkdown(input.result), "utf-8"),
    writeFile(
      decisionJsonPath,
      `${JSON.stringify(input.result, null, 2)}\n`,
      "utf-8",
    ),
  ]);

  return { triageMarkdownPath, decisionJsonPath };
}

/**
 * Render the {@link TriageResult} as a human-readable markdown document.
 * The remediation draft (if present) is embedded as a section — we do NOT
 * write a separate diff file.
 */
export function renderTriageMarkdown(result: TriageResult): string {
  const {
    report,
    scope,
    duplicate,
    verification,
    claimVerification,
    cvss,
    threatModelAlignment,
    decision,
    remediation,
  } = result;

  const lines: string[] = [];

  lines.push(`# Triage: ${report.title}`);
  lines.push("");
  lines.push(
    `- **Decision:** \`${decision.outcome}\` — \`${decision.reason}\``,
  );
  lines.push(`- **Rationale:** ${decision.rationale}`);
  lines.push(`- **Generated:** ${result.generatedAt}`);
  lines.push(`- **Target:** ${result.target}`);
  lines.push(`- **Report file:** ${result.reportPath}`);
  lines.push("");

  lines.push("## Report Summary");
  lines.push("");
  lines.push(`- Vulnerability class: ${report.vulnerabilityClass}`);
  lines.push(`- Affected URL: ${report.affectedUrl}`);
  if (report.affectedComponent) {
    lines.push(`- Affected component: ${report.affectedComponent}`);
  }
  lines.push(`- Reporter-claimed severity: ${report.claimedSeverity}`);
  lines.push(`- Attacker model: ${report.attackerModel}`);
  if (report.reporterHandle) {
    lines.push(`- Reporter: ${report.reporterHandle}`);
  }
  lines.push("");
  lines.push("### Description");
  lines.push(report.description);
  lines.push("");
  lines.push("### Claimed impact");
  lines.push(report.impact);
  lines.push("");
  if (report.references && report.references.length > 0) {
    lines.push("### CWE / References");
    for (const reference of report.references) {
      lines.push(`- ${reference}`);
    }
    lines.push("");
  }

  lines.push("## Scope check");
  lines.push("");
  lines.push(`- In scope: **${scope.inScope}**`);
  lines.push(`- Host in scope: ${scope.hostInScope}`);
  lines.push(`- Host scope source: \`${scope.hostScopeSource}\``);
  lines.push(`- Policy in scope: ${scope.policyInScope}`);
  lines.push(`- Reason: ${scope.reason}`);
  lines.push("");

  lines.push("## Duplicate check");
  lines.push("");
  lines.push(
    `- Duplicate: **${duplicate.duplicate}** (match type: ${duplicate.matchType})`,
  );
  if (duplicate.matchedTitle) {
    lines.push(`- Matched finding: "${duplicate.matchedTitle}"`);
  }
  if (duplicate.matchedEndpoint) {
    lines.push(`- Matched endpoint: \`${duplicate.matchedEndpoint}\``);
  }
  lines.push("");

  lines.push("## Live verification");
  lines.push("");
  if (!verification) {
    lines.push("_Verification was skipped._");
  } else {
    lines.push(`- Reproduced: **${verification.reproduced}**`);
    lines.push("");
    lines.push("### Evidence");
    lines.push("```");
    lines.push(verification.evidence);
    lines.push("```");
    lines.push("");
    lines.push("### Observations");
    lines.push(verification.observations);
  }
  lines.push("");

  lines.push("## Claim verification");
  lines.push("");
  if (!claimVerification) {
    lines.push("_Claim verification was skipped._");
  } else {
    lines.push(claimVerification.summary);
    lines.push("");
    lines.push("| Claim | Required | Status | Evidence |");
    lines.push("| --- | --- | --- | --- |");
    for (const claim of claimVerification.claims) {
      lines.push(
        `| ${escapeTableCell(claim.claim)} | ${claim.required} | \`${claim.status}\` | ${escapeTableCell(claim.evidence)} |`,
      );
    }
  }
  lines.push("");

  lines.push("## CVSS recalibration");
  lines.push("");
  if (!cvss) {
    lines.push("_CVSS scoring was skipped (no verified material claim set)._");
  } else {
    lines.push(`- Score: **${cvss.score}** (${cvss.severity})`);
    lines.push(`- Vector: \`${cvss.vectorString}\``);
    lines.push(`- Reasoning: ${cvss.reasoning}`);
    const claimed = report.claimedSeverity;
    if (claimed !== "UNKNOWN" && claimed !== cvss.severity.toUpperCase()) {
      lines.push(
        `- **Note:** reporter claimed \`${claimed}\` but recalibrated to \`${cvss.severity}\`.`,
      );
    }
  }
  lines.push("");

  lines.push("## Threat-model alignment");
  lines.push("");
  if (!threatModelAlignment) {
    lines.push("_Threat-model alignment was skipped._");
  } else {
    lines.push(
      `- Aligned with documented threats: **${threatModelAlignment.aligned}**`,
    );
    lines.push(
      `- Business-accepted risk: **${threatModelAlignment.businessAcceptedRisk}**`,
    );
    if (threatModelAlignment.mappedThreats.length > 0) {
      lines.push("- Mapped threats:");
      for (const t of threatModelAlignment.mappedThreats) {
        lines.push(`  - ${t}`);
      }
    }
    lines.push(`- Notes: ${threatModelAlignment.notes}`);
  }
  lines.push("");

  lines.push("## Submission readiness");
  lines.push("");
  for (const line of buildSubmissionReadiness(result)) {
    lines.push(line);
  }
  lines.push("");

  lines.push("## Suggested HackerOne action");
  lines.push("");
  if (decision.suggestedHackerOneState) {
    lines.push(`- Transition to: **${decision.suggestedHackerOneState}**`);
  } else {
    lines.push("- Transition to: _(no clean H1 state mapping)_");
  }
  lines.push("");
  lines.push("### Draft reply to reporter");
  lines.push("");
  lines.push("> " + decision.draftReplyMessage.split("\n").join("\n> "));
  lines.push("");

  if (remediation) {
    lines.push("## Suggested remediation");
    lines.push("");
    lines.push(`### ${remediation.prTitle}`);
    lines.push("");
    lines.push(remediation.prDescription);
    lines.push("");
    if (remediation.filesChanged.length > 0) {
      lines.push("### Files changed");
      lines.push("");
      for (const f of remediation.filesChanged) {
        lines.push(`- \`${f.filePath}\` — ${f.changesDescription}`);
      }
      lines.push("");
    } else {
      lines.push(
        "_No source files were changed; this is textual remediation guidance for black-box triage._",
      );
      lines.push("");
    }
  }

  lines.push("---");
  lines.push(`_Generated by apex \`/triage\`._`);

  return lines.join("\n");
}

function buildSubmissionReadiness(result: TriageResult): string[] {
  if (result.decision.outcome !== "accept") {
    return [
      "- Status: **Not submission-ready**",
      `- Reason: triage outcome is \`${result.decision.outcome}\` / \`${result.decision.reason}\`, so this should not be filed as a new HackerOne report without materially stronger evidence.`,
    ];
  }

  if (looksLikeGenericInformationDisclosure(result)) {
    return [
      "- Status: **Caution — submit only with a concrete impact chain**",
      "- Program guardrail: generic information disclosure or configuration metadata is often treated as Informative unless the report demonstrates how the behavior can be used in an attack.",
      "- Do not rely on stack traces, public client keys, server headers, framework versions, source maps, S3/CDN metadata, missing HSTS, or verbose errors by themselves.",
      "- Before submitting, verify the evidence shows direct security impact such as unauthorized data access, account/session impact, auth bypass, protected-action CSRF/CORS, exploitable cache poisoning, payment/donation/booking impact, or concrete abuse of a leaked key/config.",
    ];
  }

  return [
    "- Status: **Potentially submission-ready**",
    "- Requirement: final human review should still confirm the evidence demonstrates concrete exploitability and user, data, account, payment, or authorization impact beyond a theoretical concern.",
  ];
}

function looksLikeGenericInformationDisclosure(result: TriageResult): boolean {
  const text = [
    result.report.title,
    result.report.vulnerabilityClass,
    result.report.description,
    result.report.impact,
    result.report.affectedComponent ?? "",
    result.verification?.evidence ?? "",
    result.verification?.observations ?? "",
  ]
    .join("\n")
    .toLowerCase();

  const patterns = [
    "api key",
    "aws",
    "bucket",
    "cdn metadata",
    "cloudfront",
    "cors error",
    "dependency version",
    "error disclosure",
    "framework version",
    "hsts",
    "implementation detail",
    "internal path",
    "missing https redirect",
    "package version",
    "public key",
    "s3",
    "server header",
    "source map",
    "stack trace",
    "verbose error",
  ];

  return patterns.some((pattern) => text.includes(pattern));
}

function escapeTableCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, "<br>");
}

// Re-exported so the workflow can construct paths without re-importing path.
export function defaultOutputDir(cwd: string, reportPath: string): string {
  const slug = sanitizeForPath(reportPath);
  return join(cwd, "bounty-triage", slug);
}

function sanitizeForPath(reportPath: string): string {
  const base = reportPath.split(/[\\/]/).pop() ?? "report";
  return base.replace(/\.[^.]+$/, "").replace(/[^a-zA-Z0-9_-]+/g, "-");
}
