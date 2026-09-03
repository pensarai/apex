import { spawn } from "node:child_process";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { AttackPathSchema } from "../../../../lib/attack-path/types";
import { hasCanonicalName } from "../../../../lib/cwe/types";
import type { EvidenceFileEntry } from "../../../../lib/evidence/types";
import { createLogger } from "../../../logger/structured";
import { scopedLogger } from "../../../util/lazyLogger";
import {
  type CVSSScorerInput,
  type CVSSScorerResult,
  scoreFindingWithCVSS,
} from "../../specialized/cvssScorer";
import type {
  FindingJudgeInput,
  FindingJudgeResult,
} from "../../specialized/findingJudge";
import type { Finding } from "../types";
import {
  assertFindingEndpointInScope,
  ScopeViolationError,
} from "./scopeGuard";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("document-finding"));

export const documentVulnerabilityInputSchema = z.object({
  title: z.string().describe("Finding title"),
  description: z.string().describe("Detailed description of the finding"),
  impact: z.string().describe("Potential impact if exploited"),
  evidence: z.string().describe("Evidence/proof of the vulnerability"),
  materiality: z
    .object({
      exploitPath: z
        .string()
        .describe("Concrete exploit path confirmed by the POC"),
      securityImpact: z
        .string()
        .describe("Material security impact if the exploit succeeds"),
      affectedAssetOrAbusePath: z
        .string()
        .describe(
          "The non-public asset, privileged action, state change, denial of service, account takeover, or other abuse path affected",
        ),
      falsePositiveRationale: z
        .string()
        .describe(
          "Why common false-positive traps do not apply (public endpoint, local/demo context, generic errors, best-practice-only gaps, public identifiers, missing non-sensitive controls)",
        ),
    })
    .describe(
      "Materiality checklist proving this is more than a low-signal observation",
    ),
  endpoint: z.string().describe("The affected endpoint or URL"),
  remediation: z.string().describe("Steps to fix the issue"),
  references: z.string().optional().describe("CVE, CWE, or related references"),
  vulnerabilityClass: z
    .string()
    .optional()
    .describe(
      "The class of vulnerability (e.g., sqli, xss, command-injection, idor, ssrf, path-traversal, crypto, cve, hardcoded-credentials, information-disclosure, missing-authentication)",
    ),
  toolCallDescription: z
    .string()
    .optional()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Documenting SQL injection finding')",
    ),
  pocName: z.string().describe("Short descriptive name for the POC"),
  pocType: z.enum(["bash", "python", "javascript"]).describe("Script language"),
  pocContent: z.string().describe("The full POC script content"),
  pocDescription: z.string().describe("What this POC demonstrates"),
  attackPath: AttackPathSchema.optional().describe(
    "Required ordered member-to-member hop chain when the finding spans multiple System members; do not leave this chain only in narrative fields",
  ),
});

export type DocumentVulnerabilityInput = z.infer<
  typeof documentVulnerabilityInputSchema
>;

function formatMateriality(input: DocumentVulnerabilityInput): string {
  return [
    input.evidence,
    "",
    "Materiality:",
    `- Exploit path: ${input.materiality.exploitPath}`,
    `- Security impact: ${input.materiality.securityImpact}`,
    `- Affected asset or abuse path: ${input.materiality.affectedAssetOrAbusePath}`,
    `- False-positive rationale: ${input.materiality.falsePositiveRationale}`,
  ].join("\n");
}

type PocType = "bash" | "python" | "javascript";

const POC_RUNNERS: Record<PocType, string> = {
  bash: "bash",
  python: "python3",
  javascript: "node",
};

const POC_EXTENSIONS: Record<PocType, string> = {
  bash: ".sh",
  python: ".py",
  javascript: ".js",
};

const EVIDENCE_FILE_THRESHOLD = 20_000;
const MAX_OUTPUT_BYTES = 1_024 * 1_024; // 1 MB cap for stdout/stderr

const FALLBACK_CVSS: CVSSScorerResult = {
  score: 5.0,
  severity: "MEDIUM",
  vectorString:
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
  metrics: {
    AV: "N",
    AC: "L",
    AT: "N",
    PR: "N",
    UI: "N",
    VC: "L",
    VI: "L",
    VA: "N",
    SC: "N",
    SI: "N",
    SA: "N",
    E: "A",
  },
  scoreType: "CVSS-BT",
  reasoning: "CVSS scoring unavailable — using conservative MEDIUM default.",
  cwes: [],
};

function slugify(str: string, maxLen: number): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .substring(0, maxLen);
}

export function documentVulnerability(ctx: ToolContext) {
  const { session } = ctx;

  return tool({
    description: `Document a CONFIRMED security vulnerability by providing your proof-of-concept script and finding details.

This tool handles the full vulnerability documentation lifecycle:
1. Creates and executes your POC script (bash, python, or javascript)
2. If the POC fails (exit != 0), returns the failure output so you can revise pocContent and retry
3. Validates the finding with an automated judge to ensure the POC genuinely demonstrates the claimed vulnerability
4. If the judge rejects, returns rejection reasoning so you can address concerns and retry
5. Scores the finding with CVSS 4.0 (severity is determined automatically)
6. Deduplicates and persists the finding

CRITICAL RULES — READ BEFORE CALLING:
- ONLY call this for actual security vulnerabilities you have verified and can exploit
- Provide your POC script inline via pocContent — do NOT create it separately
- POC must exit 0 on success (vulnerability confirmed), non-zero on failure
- POC must print clear evidence of exploitation to stdout
- Fill the materiality checklist with the concrete exploit path, material security impact, affected non-public asset or abuse path, and why common false-positive traps do not apply
- When a finding spans multiple System members, populate attackPath with every hop in order; do not leave the chain only in the description or evidence
- If the tool returns a POC failure or judge rejection, revise your approach and call again
- Do NOT use this for: positive observations, informational notes, testing limitations, or anything that is not an exploitable security vulnerability
- If you could not exploit a vulnerability, do NOT call this tool — mention it in your final response summary instead`,
    inputSchema: documentVulnerabilityInputSchema,
    execute: async (input) => {
      // Defense in depth: reject findings whose endpoint host is outside the
      // immutable engagement scope so a routing error can't write
      // infrastructure findings into the shared customer registry.
      try {
        assertFindingEndpointInScope(input.endpoint, ctx);
      } catch (error) {
        if (error instanceof ScopeViolationError) {
          return {
            success: false,
            error: error.message,
            message: `Finding endpoint rejected — out of scope: ${error.message}`,
          };
        }
        throw error;
      }

      try {
        // Early dedup check — avoid POC execution + LLM calls for known vulns
        const materializedEvidence = formatMateriality(input);

        if (ctx.findingsRegistry) {
          const quickCheck = ctx.findingsRegistry.isDuplicate({
            title: input.title,
            description: input.description,
            endpoint: input.endpoint,
            severity: "MEDIUM",
            impact: input.impact,
            evidence: materializedEvidence,
            pocPath: "",
            remediation: input.remediation,
            ...(input.references && { references: input.references }),
            ...(input.vulnerabilityClass && {
              vulnerabilityClass: input.vulnerabilityClass,
            }),
          });
          if (quickCheck.duplicate) {
            const matchTitle = quickCheck.matchedFinding?.title ?? "unknown";
            return {
              success: false,
              duplicate: true,
              matchType: quickCheck.matchType,
              matchedFinding: matchTitle,
              message: `Duplicate finding (${quickCheck.matchType}): already documented as "${matchTitle}". Skipping.`,
            };
          }
        }

        // Phase 1: Write & execute POC
        const pocResult = ctx.sandbox
          ? await executeSandboxPoc(ctx, input)
          : await executeLocalPoc(ctx, input);

        if (!pocResult.success) {
          return {
            success: false,
            pocFailed: true,
            stdout: pocResult.stdout,
            stderr: pocResult.stderr,
            exitCode: pocResult.exitCode,
            message: `POC exited with code ${pocResult.exitCode ?? "unknown"}. Review the output and revise pocContent.`,
          };
        }

        const { filename, stdout, stderr, exitCode } = pocResult;
        const pocPath = `pocs/${filename}`;

        // Phase 2: LLM Finding Judge
        const judgeInput: FindingJudgeInput = {
          pocScript: input.pocContent,
          pocType: input.pocType,
          pocPath,
          target: ctx.target ?? ctx.session.targets[0],
          pocOutput: {
            stdout: stdout || "",
            stderr: stderr || "",
            exitCode: exitCode ?? 0,
          },
          claim: {
            title: input.title,
            description: input.description,
            impact: input.impact,
            evidence: materializedEvidence,
            endpoint: input.endpoint,
            vulnerabilityClass: input.vulnerabilityClass,
          },
        };

        // Run the judge as a proper nested subagent through the spawner —
        // child bus + explicit lifecycle so its stream nests under the worker
        // that invoked document_vulnerability. `error` is only set by the
        // infrastructure-failure fallback, so a judge that completed and
        // rejected the finding still counts as "completed".
        const spawner = ctx.subagentSpawner;
        const judgeResult: FindingJudgeResult =
          await spawner.spawn<FindingJudgeResult>({
            spec: { type: "finding-judge", judgeInput, target: ctx.target },
            runtime: {
              session: ctx.session,
              model: ctx.model!,
              authConfig: ctx.authConfig,
              abortSignal: ctx.abortSignal,
              sandbox: ctx.sandbox,
              enableThinking: ctx.enableThinking,
              thinkingEffort: ctx.thinkingEffort,
              openAIReasoningEffort: ctx.openAIReasoningEffort,
              languageModelMiddleware: ctx.languageModelMiddleware,
              usageRecorder: ctx.usageRecorder,
              streamIdFactory: ctx.streamIdFactory,
            },
            parentBus: ctx.eventBus,
            subagentName: "Finding Judge",
            lifecycleInput: { title: input.title, endpoint: input.endpoint },
            parentSubagentId: ctx.subagentId,
            resolveStatus: (r) => (r.error ? "failed" : "completed"),
          });

        if (!judgeResult.valid) {
          cleanupPocFiles(ctx, filename);
          return {
            success: false,
            judgeRejected: true,
            judgeReasoning: judgeResult.reasoning,
            judgeConcerns: judgeResult.concerns,
            judgeConfidence: judgeResult.confidence,
            message: `Finding rejected by validation judge: ${judgeResult.reasoning}`,
          };
        }

        const isVulnerability = judgeResult.findingType === "vulnerability";

        // Write sidecar only after judge acceptance (avoid wasted I/O on rejection)
        writePocOutputSidecar(
          ctx.session.pocsPath,
          filename,
          stdout || "",
          stderr || "",
          exitCode ?? 0,
          input.pocDescription,
        );

        // Build structured evidence file links
        const evidenceFiles: EvidenceFileEntry[] = [];

        evidenceFiles.push({
          path: `pocs/${filename}.output.json`,
          type: "poc-output",
          description: `POC execution output for ${filename}`,
        });

        // Phase 3: CVSS 4.0 scoring
        const timestamp = new Date().toISOString();

        const outputDir = isVulnerability
          ? session.findingsPath
          : join(session.rootPath, "informational");

        if (!isVulnerability) {
          mkdirSync(outputDir, { recursive: true });
        }

        let evidenceForPrompt = materializedEvidence;

        if (materializedEvidence.length > EVIDENCE_FILE_THRESHOLD) {
          const evidenceFilename = `${timestamp.split("T")[0]}-${slugify(input.title, 40)}-evidence.txt`;
          const evidenceFilePath = join(outputDir, evidenceFilename);
          writeFileSync(evidenceFilePath, materializedEvidence);
          evidenceForPrompt =
            materializedEvidence.substring(0, EVIDENCE_FILE_THRESHOLD) +
            `\n... [truncated — full output saved to ${evidenceFilename}]`;
          const pathPrefix = isVulnerability ? "findings" : "informational";
          evidenceFiles.push({
            path: `${pathPrefix}/${evidenceFilename}`,
            type: "raw-evidence",
            description: `Full evidence output (${materializedEvidence.length} bytes)`,
          });
        }

        let cvssResult: CVSSScorerResult = FALLBACK_CVSS;
        let cvssWarning: string | undefined;

        if (!isVulnerability) {
          cvssResult = {
            score: 0,
            severity: "LOW",
            vectorString: "",
            metrics: FALLBACK_CVSS.metrics,
            scoreType: "N/A",
            reasoning: `Classified as ${judgeResult.findingType} — CVSS scoring skipped.`,
            cwes: [],
          };
          cvssWarning = `Classified as ${judgeResult.findingType} — not scored.`;
        } else {
          const cvssInput: CVSSScorerInput = {
            finding: {
              title: input.title,
              description: input.description,
              impact: input.impact,
              evidence: evidenceForPrompt,
              endpoint: input.endpoint,
              remediation: input.remediation,
              vulnerabilityClass: input.vulnerabilityClass,
            },
            agentMessages: [],
          };

          const MAX_CVSS_ATTEMPTS = 2;
          for (let attempt = 0; attempt < MAX_CVSS_ATTEMPTS; attempt++) {
            try {
              cvssResult = await scoreFindingWithCVSS(
                cvssInput,
                ctx.model!,
                ctx.authConfig,
                ctx.abortSignal,
              );
              break;
            } catch (err: unknown) {
              const msg = err instanceof Error ? err.message : String(err);

              if (
                attempt >= MAX_CVSS_ATTEMPTS - 1 ||
                ctx.abortSignal?.aborted
              ) {
                cvssWarning = `CVSS scoring failed after ${attempt + 1} attempt(s) (${msg}), using estimated MEDIUM severity.`;
                cvssResult = FALLBACK_CVSS;
                break;
              }

              await new Promise<void>((resolve) => {
                const timer = setTimeout(resolve, 2_000);
                if (ctx.abortSignal) {
                  const onAbort = () => {
                    clearTimeout(timer);
                    resolve();
                  };
                  if (ctx.abortSignal.aborted) {
                    clearTimeout(timer);
                    resolve();
                  } else {
                    ctx.abortSignal.addEventListener("abort", onAbort, {
                      once: true,
                    });
                  }
                }
              });

              if (ctx.abortSignal?.aborted) {
                cvssWarning = `CVSS scoring cancelled, using estimated MEDIUM severity.`;
                cvssResult = FALLBACK_CVSS;
                break;
              }
            }
          }
        }

        const severity =
          cvssResult.severity === "NONE" ? "LOW" : cvssResult.severity;

        // Phase 4: Build finding and register with dedup
        const finding: Finding = {
          title: input.title,
          description: input.description,
          impact: input.impact,
          evidence: materializedEvidence,
          endpoint: input.endpoint,
          pocPath,
          remediation: input.remediation,
          ...(input.references && { references: input.references }),
          ...(input.vulnerabilityClass && {
            vulnerabilityClass: input.vulnerabilityClass,
          }),
          severity: severity as Finding["severity"],
          ...(evidenceFiles.length > 0 && { evidenceFiles }),
          ...(input.attackPath &&
            input.attackPath.length > 0 && { attackPath: input.attackPath }),
        };

        if (isVulnerability && ctx.findingsRegistry) {
          const check = await ctx.findingsRegistry.register(finding);
          if (check.duplicate) {
            cleanupPocFiles(ctx, filename);
            const matchTitle = check.matchedFinding?.title ?? "unknown";
            return {
              success: false,
              duplicate: true,
              matchType: check.matchType,
              matchedFinding: matchTitle,
              message: `Duplicate finding (${check.matchType}): already documented as "${matchTitle}". Skipping.`,
            };
          }
        }

        // Phase 5: Persist finding
        const findingWithMeta = {
          ...finding,
          timestamp,
          sessionId: session.id,
          target: session.targets[0],
          pocOutput: {
            stdout: stdout || "",
            stderr: stderr || "",
            exitCode: exitCode ?? 0,
            executedAt: timestamp,
          },
          cwes: cvssResult.cwes,
          cvss: {
            scored: cvssWarning === undefined,
            score: cvssResult.score,
            severity: cvssResult.severity,
            vectorString: cvssWarning ? "" : cvssResult.vectorString,
            metrics: cvssResult.metrics,
            scoreType: cvssResult.scoreType,
            reasoning: cvssResult.reasoning,
          },
          judge: {
            valid: judgeResult.valid,
            findingType: judgeResult.findingType,
            confidence: judgeResult.confidence,
            reasoning: judgeResult.reasoning,
            concerns: judgeResult.concerns,
            verificationSteps: judgeResult.verificationSteps,
            toolEvidence: judgeResult.toolEvidence,
            reproducedPoc: judgeResult.reproducedPoc,
            webResearchUsed: judgeResult.webResearchUsed,
            limitations: judgeResult.limitations,
            ...(judgeResult.error && { error: judgeResult.error }),
          },
        };

        const findingId = `${timestamp.split("T")[0]}-${slugify(finding.title, 50)}`;
        const jsonFilename = `${findingId}.json`;
        const mdFilename = `${findingId}.md`;
        const jsonPath = join(outputDir, jsonFilename);
        const mdPath = join(outputDir, mdFilename);

        try {
          writeFileSync(jsonPath, JSON.stringify(findingWithMeta, null, 2));

          const cvssSection = cvssWarning
            ? `## CVSS 4.0 Assessment

**Warning:** ${cvssWarning}

**Score:** ${cvssResult.score} / 10.0 (${cvssResult.severity})
**Score Type:** ${cvssResult.scoreType}`
            : `## CVSS 4.0 Assessment

**Score:** ${cvssResult.score} / 10.0 (${cvssResult.severity})
**Vector:** \`${cvssResult.vectorString}\`
**Score Type:** ${cvssResult.scoreType}

**Reasoning:** ${cvssResult.reasoning}`;

          const cweSection = cvssResult.cwes?.length
            ? `## CWE Classification

${cvssResult.cwes.map((cwe) => `- **${cwe.id}**${hasCanonicalName(cwe) ? `: ${cwe.name}` : ""} — ${cwe.reasoning}`).join("\n")}`
            : "";

          const hasLargeEvidence = finding.evidenceFiles?.some(
            (ef) => ef.type === "raw-evidence",
          );
          const evidenceSection = hasLargeEvidence
            ? `## Evidence

\`\`\`
${finding.evidence.substring(0, 5_000)}
\`\`\`

> Full evidence output: see evidence files below`
            : `## Evidence

\`\`\`
${finding.evidence}
\`\`\``;

          const evidenceFilesSection = finding.evidenceFiles?.length
            ? `## Evidence Files

${finding.evidenceFiles.map((ef) => `- **[${ef.type}]** \`${ef.path}\` — ${ef.description}`).join("\n")}`
            : "";

          const headerLines = [
            `**Severity:** ${cvssWarning ? `${finding.severity} (estimated)` : finding.severity}`,
            `**CVSS 4.0 Score:** ${cvssWarning ? "N/A" : `${cvssResult.score} (${cvssResult.severity})`}`,
            ...(cvssWarning
              ? []
              : [`**Vector:** \`${cvssResult.vectorString}\``]),
            `**Target:** ${session.targets[0]}`,
            `**Endpoint:** ${finding.endpoint}`,
            `**Date:** ${timestamp}`,
            `**Session:** ${session.id}`,
          ];

          const markdown = `# ${finding.title}

${headerLines.join("  \n")}

## Description

${finding.description}

## Impact

${finding.impact}

${cvssSection}

${cweSection ? `${cweSection}\n\n` : ""}${evidenceSection}

${evidenceFilesSection ? `${evidenceFilesSection}\n\n` : ""}## POC

Path: \`${finding.pocPath}\`

## Remediation

${finding.remediation}

${finding.references ? `## References\n\n${finding.references}` : ""}

---

*This finding was automatically documented by the Pensar penetration testing agent.*
`;

          writeFileSync(mdPath, markdown);

          if (isVulnerability) {
            const summaryPath = join(session.rootPath, "findings-summary.md");
            const cweTag = cvssResult.cwes?.length
              ? ` (${cvssResult.cwes.map((c) => c.id).join(", ")})`
              : "";
            const cvssTag = cvssWarning
              ? "(estimated)"
              : `(CVSS ${cvssResult.score})`;
            const summaryEntry = `- [${finding.severity}] ${cvssTag}${cweTag} ${finding.title} - \`findings/${mdFilename}\`\n`;

            try {
              appendFileSync(summaryPath, summaryEntry);
            } catch {
              const header = `# Findings Summary\n\n**Target:** ${session.targets[0]}  \n**Session:** ${session.id}\n\n## All Findings\n\n`;
              writeFileSync(summaryPath, header + summaryEntry);
            }
          }
        } catch (writeError: unknown) {
          if (isVulnerability && ctx.findingsRegistry) {
            await ctx.findingsRegistry.unregister(finding);
          }
          throw writeError;
        }

        const typeTag = isVulnerability
          ? finding.severity
          : judgeResult.findingType.toUpperCase();
        const resultMessage = cvssWarning
          ? `Finding documented: [${typeTag}] ${finding.title} (${cvssWarning})`
          : `Finding documented: [${typeTag}] ${finding.title}`;

        return {
          success: true,
          finding: findingWithMeta,
          filepath: mdPath,
          message: resultMessage,
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          error: errorMsg,
          message: `Failed to document finding: ${errorMsg}`,
        };
      }
    },
  });
}

// ---------------------------------------------------------------------------
// POC Execution
// ---------------------------------------------------------------------------

interface PocExecResult {
  success: boolean;
  filename: string;
  stdout?: string;
  stderr?: string;
  exitCode?: number;
}

async function executeLocalPoc(
  ctx: ToolContext,
  input: DocumentVulnerabilityInput,
): Promise<PocExecResult> {
  const pocsPath = ctx.session.pocsPath;
  if (!existsSync(pocsPath)) {
    mkdirSync(pocsPath, { recursive: true });
  }

  const { filename, pocContent } = preparePoc(input);
  const pocPath = join(pocsPath, filename);

  writeFileSync(pocPath, pocContent);
  chmodSync(pocPath, 0o755);

  const { stdout, stderr, exitCode } = await runScript(
    POC_RUNNERS[input.pocType],
    pocPath,
    60_000,
    ctx.abortSignal,
  );

  if (exitCode !== 0) {
    try {
      unlinkSync(pocPath);
    } catch {
      /* cleanup best-effort */
    }
    return { success: false, filename, stdout, stderr, exitCode };
  }

  return { success: true, filename, stdout, stderr, exitCode };
}

async function executeSandboxPoc(
  ctx: ToolContext,
  input: DocumentVulnerabilityInput,
): Promise<PocExecResult> {
  const { filename, pocContent } = preparePoc(input);

  const localPocsPath = ctx.session.pocsPath;
  if (!existsSync(localPocsPath)) {
    mkdirSync(localPocsPath, { recursive: true });
  }
  const localPocPath = join(localPocsPath, filename);

  writeFileSync(localPocPath, pocContent);

  // Pipeline sandbox setup into a single command to reduce round-trips
  const sandboxPocPath = `/tmp/pocs/${filename}`;
  const base64Content = Buffer.from(pocContent).toString("base64");
  await ctx.sandbox!.execute(
    `mkdir -p /tmp/pocs && echo "${base64Content}" | base64 -d > ${sandboxPocPath} && chmod +x ${sandboxPocPath}`,
  );

  const runner = POC_RUNNERS[input.pocType];
  const result = await ctx.sandbox!.execute(
    `cd /tmp && ${runner} ${sandboxPocPath}`,
    { timeout: 60 },
  );

  const executionSuccess = result.success || result.exitCode === 0;

  if (!executionSuccess) {
    await ctx.sandbox!.execute(`rm -f ${sandboxPocPath}`);
    try {
      unlinkSync(localPocPath);
    } catch {
      /* cleanup best-effort */
    }
    return {
      success: false,
      filename,
      stdout: result.stdout || "(no output)",
      stderr:
        (result.stderr || "POC execution failed") +
        "\n\nPOC file has been deleted.",
      exitCode: result.exitCode,
    };
  }

  return {
    success: true,
    filename,
    stdout: result.stdout || "(no output)",
    stderr: result.stderr || "(no errors)",
    exitCode: result.exitCode,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function cleanupPocFiles(ctx: ToolContext, filename: string): void {
  try {
    unlinkSync(join(ctx.session.pocsPath, filename));
  } catch {
    /* best-effort */
  }
  try {
    unlinkSync(join(ctx.session.pocsPath, `${filename}.output.json`));
  } catch {
    /* best-effort */
  }
}

function sanitizeFilename(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .substring(0, 50);
}

/**
 * Validates PoC script for POSIX portability issues.
 * Returns array of warning messages for non-portable patterns.
 */
export function validatePocPortability(
  content: string,
  pocType: PocType,
): string[] {
  const warnings: string[] = [];

  // Only validate shell scripts (bash) for now
  // Python and JavaScript have their own portable runtimes
  if (pocType !== "bash") {
    return warnings;
  }

  // Check for grep -P or grep -oP (Perl regex - not portable)
  // Match -P anywhere after grep (e.g., -P, -oP, -Po, grep -i -P, etc.)
  if (
    /grep\s+.*?-[a-zA-Z]*P[a-zA-Z]*\b/.test(content) ||
    /grep\s+.*?--perl-regexp\b/.test(content)
  ) {
    warnings.push(
      "Non-portable: grep -P or grep -oP (Perl regex) detected. Use grep -E (extended regex) or grep -o instead for macOS/BusyBox compatibility.",
    );
  }

  // Check for bare bc usage (not installed in sandbox)
  // Match bc as a standalone command (piped, standalone, or in command substitution)
  if (
    /(\|\s*bc\b|^\s*bc\b|\$\(\s*bc\b|`\s*bc\b)/m.test(content) &&
    !/which\s+bc|command\s+-v\s+bc/.test(content)
  ) {
    warnings.push(
      "Non-portable: bc command detected but not installed in sandbox. Use $(( )) shell arithmetic, awk, or python3 -c instead.",
    );
  }

  // Check for GNU stat with -c flag (with word boundary to avoid matching netstat, vmstat, etc.)
  if (/\bstat\s+-c/.test(content)) {
    warnings.push(
      "Non-portable: stat -c is GNU-specific. Use stat -f on BSD/macOS or portable alternatives.",
    );
  }

  // Check for GNU date with --rfc-3339 or similar (with word boundary to avoid matching update, etc.)
  if (/\bdate\s+--[a-z]/.test(content)) {
    warnings.push(
      "Non-portable: GNU date long options (--rfc-3339, etc.) may not work on BSD/macOS. Use date with standard format strings instead.",
    );
  }

  // Check for seq without command check
  if (
    /\bseq\b/.test(content) &&
    !/which\s+seq|command\s+-v\s+seq/.test(content)
  ) {
    warnings.push(
      "Potentially non-portable: seq may not be available. Consider using for i in $(seq ...) with a fallback or brace expansion {1..N}.",
    );
  }

  return warnings;
}

function preparePoc(input: {
  pocName: string;
  pocType: PocType;
  pocContent: string;
  pocDescription: string;
}): { filename: string; pocContent: string } {
  const sanitizedName = sanitizeFilename(input.pocName);
  const filename = `poc_${sanitizedName}${POC_EXTENSIONS[input.pocType]}`;

  let pocContent = input.pocContent.trim();

  // Validate portability before preparing the script
  const portabilityWarnings = validatePocPortability(pocContent, input.pocType);
  if (portabilityWarnings.length > 0) {
    log.warn(
      `PoC portability warnings for ${filename}: ${portabilityWarnings.join("; ")}`,
    );
  }

  if (!pocContent.startsWith("#!")) {
    const shebangs: Record<string, string> = {
      bash: "#!/bin/bash\nset -e\n\n",
      python: "#!/usr/bin/env python3\n\n",
      javascript: "#!/usr/bin/env node\n\n",
    };
    pocContent = shebangs[input.pocType] + pocContent;
  }

  const commentChar = input.pocType === "javascript" ? "//" : "#";
  const header = `${commentChar} POC: ${input.pocDescription}\n${commentChar} Created: ${new Date().toISOString()}\n\n`;
  pocContent = pocContent.replace(/^#!.*\n/, (match) => match + header);

  return { filename, pocContent };
}

function writePocOutputSidecar(
  pocsPath: string,
  filename: string,
  stdout: string,
  stderr: string,
  exitCode: number,
  description: string,
): void {
  try {
    const outputPath = join(pocsPath, `${filename}.output.json`);
    writeFileSync(
      outputPath,
      JSON.stringify(
        {
          stdout,
          stderr,
          exitCode,
          executedAt: new Date().toISOString(),
          pocFile: filename,
          description,
        },
        null,
        2,
      ),
    );
  } catch {
    /* non-critical */
  }
}

function runScript(
  runner: string,
  scriptPath: string,
  timeout: number,
  abortSignal?: AbortSignal,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const child = spawn(runner, [scriptPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });

    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let killed = false;
    let resolved = false;

    let abortCleanup: (() => void) | undefined;
    if (abortSignal) {
      const handler = () => killProcess();
      abortSignal.addEventListener("abort", handler, { once: true });
      abortCleanup = () => abortSignal.removeEventListener("abort", handler);
    }

    const safeResolve = (result: {
      stdout: string;
      stderr: string;
      exitCode: number;
    }) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeoutTimer);
        abortCleanup?.();
        resolve(result);
      }
    };

    const killProcess = () => {
      if (killed) return;
      killed = true;

      try {
        if (child.pid && process.platform !== "win32") {
          process.kill(-child.pid, "SIGTERM");
        } else {
          child.kill("SIGTERM");
        }
      } catch {
        /* process may have already exited */
      }

      setTimeout(() => {
        try {
          if (child.pid && process.platform !== "win32") {
            process.kill(-child.pid, "SIGKILL");
          } else {
            child.kill("SIGKILL");
          }
        } catch {
          /* process may have already exited */
        }

        safeResolve({ stdout, stderr, exitCode: 1 });
      }, 5000);
    };

    const timeoutTimer = setTimeout(killProcess, timeout);

    child.stdout.on("data", (data: Buffer) => {
      if (stdoutBytes < MAX_OUTPUT_BYTES) {
        const chunk = data.toString();
        stdout += chunk;
        stdoutBytes += data.length;
      }
    });
    child.stderr.on("data", (data: Buffer) => {
      if (stderrBytes < MAX_OUTPUT_BYTES) {
        const chunk = data.toString();
        stderr += chunk;
        stderrBytes += data.length;
      }
    });

    child.on("close", (code) => {
      safeResolve({ stdout, stderr, exitCode: code ?? 1 });
    });

    child.on("error", () => {
      safeResolve({ stdout, stderr, exitCode: 1 });
    });
  });
}
