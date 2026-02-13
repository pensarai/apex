/**
 * POC Generation and Finding Documentation Tools
 *
 * These tools enable the MetaTestingAgent to:
 * 1. Create and execute POC scripts (bash preferred, python supported)
 * 2. Document confirmed vulnerabilities with evidence
 */

import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { promisify } from "util";
import { exec } from "child_process";
import {
  existsSync,
  writeFileSync,
  chmodSync,
  unlinkSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  appendFileSync,
} from "fs";
import { nanoid } from "nanoid";
import { Logger } from "../logger";
import type { Session } from "../../session";
import type {
  CreatePocInput,
  CreatePocResult,
  DocumentFindingInput,
  DocumentFindingResult,
  MetaTestingSessionInfo,
} from "./types";
import { CreatePocSchema, DocumentFindingSchema } from "./types";
import type { ExecuteCommandOpts, ExecuteCommandResult } from "../tools";
import { scoreFindingWithCVSS, DEFAULT_CVSS_MODEL } from "../cvssScorer";
import type { AIModel } from "../../ai";
import type { AIAuthConfig } from "../../ai/utils";
import type { CVSS4Metrics } from "../../../lib/cvss";

/** Options for CVSS scoring in document_finding tool */
export interface DocumentFindingCVSSOptions {
  /** Enable CVSS scoring (from session config) */
  enableCvssScoring?: boolean;
  /** Model to use for CVSS scoring (default: claude-4-5-haiku) */
  cvssModel?: AIModel;
  /** Callback to get current agent messages for context */
  getMessages?: () => unknown[];

  /** Auth config for AI provider authentication (e.g., Bedrock credentialProvider) */
  authConfig?: AIAuthConfig;
}

const execAsync = promisify(exec);

const MAX_POC_ATTEMPTS = 3;

function sanitizeFilename(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .substring(0, 50);
}

export function createPocTool(
  session: MetaTestingSessionInfo,
  logger: Logger,
  toolOverride?: {
    execute_command?: (
      opts: ExecuteCommandOpts
    ) => Promise<ExecuteCommandResult>;
  }
) {
  // Track POC attempts per approach
  const pocAttempts = new Map<string, number>();
  const pocPaths: string[] = [];

  const create_poc = tool({
    description: `Create and test a Proof-of-Concept script.

Supported languages:
- **Bash** (.sh) - Preferred for simple HTTP/curl-based POCs
- **Python** (.py) - For complex scenarios with requests library
- **JavaScript** (.js) - For Node.js-based exploitation

This tool:
1. Creates the POC file in the pocs/ directory
2. Makes executable and runs it (bash via sh, python via python3, js via node)
3. Returns execution output for analysis
4. **Deletes the file if execution fails**

POC requirements:
- Exit 0 on success (vuln confirmed), 1 on failure
- Print clear evidence of exploitation
- Include rate limiting (sleep between requests)

Max ${MAX_POC_ATTEMPTS} attempts per approach before pivoting.`,
    inputSchema: CreatePocSchema,
    execute: async (poc: CreatePocInput): Promise<CreatePocResult> => {
      const approachKey = `${poc.pocName}_${poc.description.substring(0, 30)}`;
      const currentAttempts = (pocAttempts.get(approachKey) || 0) + 1;
      pocAttempts.set(approachKey, currentAttempts);

      logger.info(
        `POC attempt ${currentAttempts}/${MAX_POC_ATTEMPTS}: ${poc.pocName} (${poc.pocType})`
      );

      try {
        const pocsPath = session.pocsPath;
        if (!existsSync(pocsPath)) {
          mkdirSync(pocsPath, { recursive: true });
        }

        const extension =
          poc.pocType === "bash"
            ? ".sh"
            : poc.pocType === "python"
            ? ".py"
            : ".js";
        const sanitizedName = sanitizeFilename(poc.pocName);
        const filename = `poc_${sanitizedName}${extension}`;
        const pocPath = join(pocsPath, filename);
        const relativePocPath = `pocs/${filename}`;

        let pocContent = poc.pocContent.trim();

        // Add appropriate header if missing
        if (poc.pocType === "bash") {
          if (!pocContent.startsWith("#!")) {
            pocContent = "#!/bin/bash\n" + pocContent;
          }
          // Add header comment if not present
          if (!pocContent.includes("# POC:")) {
            const header = `#!/bin/bash
# POC: ${poc.description}
# Created: ${new Date().toISOString()}
# Attempt: ${currentAttempts}/${MAX_POC_ATTEMPTS}

set -e  # Exit on error

`;
            pocContent = header + pocContent.replace(/^#!\/bin\/bash\s*\n/, "");
          }
        } else if (poc.pocType === "python") {
          // Python
          if (!pocContent.startsWith("#!") && !pocContent.startsWith("#!/")) {
            pocContent = "#!/usr/bin/env python3\n" + pocContent;
          }
          // Add header comment if not present
          if (!pocContent.includes("# POC:")) {
            const header = `#!/usr/bin/env python3
# POC: ${poc.description}
# Created: ${new Date().toISOString()}
# Attempt: ${currentAttempts}/${MAX_POC_ATTEMPTS}

`;
            pocContent = header + pocContent.replace(/^#!.*\n/, "");
          }
        } else {
          // JavaScript (Node.js)
          if (!pocContent.startsWith("#!/")) {
            pocContent = "#!/usr/bin/env node\n" + pocContent;
          }
          // Add header comment if not present
          if (!pocContent.includes("// POC:")) {
            const header = `#!/usr/bin/env node
// POC: ${poc.description}
// Created: ${new Date().toISOString()}
// Attempt: ${currentAttempts}/${MAX_POC_ATTEMPTS}

`;
            pocContent = header + pocContent.replace(/^#!.*\n/, "");
          }
        }

        writeFileSync(pocPath, pocContent);
        logger.info(`POC written to: ${relativePocPath}`);

        let stdout = "";
        let stderr = "";
        let exitCode = 0;

        try {
          if (poc.pocType === "bash" || poc.pocType === "javascript") {
            chmodSync(pocPath, 0o755);
          }

          // Use sandboxed execute_command if available (for benchmark/remote execution)
          if (toolOverride?.execute_command) {
            // For sandbox execution, pass the POC content directly
            const pocBase64 = Buffer.from(pocContent).toString("base64");
            const execCommand =
              poc.pocType === "bash"
                ? `echo '${pocBase64}' | base64 -d | bash`
                : poc.pocType === "python"
                ? `echo '${pocBase64}' | base64 -d | python3`
                : `echo '${pocBase64}' | base64 -d | node`;

            const execResult = await toolOverride.execute_command({
              command: execCommand,
              timeout: 60000, // 60 second timeout for POCs
              toolCallDescription: `Executing ${poc.pocType} POC: ${poc.pocName}`,
            });

            stdout = execResult.stdout || "";
            stderr = execResult.stderr || "";

            if (!execResult.success || execResult.error) {
              throw {
                message: execResult.error || "POC execution failed",
                code: 1,
                stdout,
                stderr,
              };
            }
          } else {
            // Local execution
            const execCommand =
              poc.pocType === "bash"
                ? pocPath
                : poc.pocType === "python"
                ? `python3 ${pocPath}`
                : `node ${pocPath}`;

            const result = await execAsync(execCommand, {
              timeout: 60000,
              maxBuffer: 1024 * 1024,
              cwd: session.rootPath,
            });

            stdout = result.stdout;
            stderr = result.stderr;
          }

          logger.info(`POC executed successfully: ${filename}`);
          pocPaths.push(relativePocPath);

          return {
            success: true,
            pocPath: relativePocPath,
            execution: {
              success: true,
              exitCode: 0,
              stdout: stdout || "(no output)",
              stderr: stderr || "(no errors)",
            },
            message: `POC created and executed successfully at: ${relativePocPath}

**Execution Output:**
STDOUT:
\`\`\`
${stdout || "(no output)"}
\`\`\`

STDERR:
\`\`\`
${stderr || "(no errors)"}
\`\`\`

**VALIDATION REQUIRED:** Analyze the output above.
- If output confirms vulnerability exploitation → call document_finding with pocPath: "${relativePocPath}"
- If output shows failure or inconclusive → create improved POC or pivot approach

Remember to update your confidence based on this result:
VALIDATION: Outcome: [yes/no + evidence] | Confidence: BEFORE [X%] → AFTER [Y%]`,
          };
        } catch (execError) {
          // Execution failed - but KEEP the POC file for:
          // 1. Manual execution/verification later
          // 2. Documentation purposes (the POC content is valid, target may just be down)
          // 3. Reference in document_finding if evidence was gathered earlier
          logger.info(`POC execution failed but keeping file: ${filename}`);
          pocPaths.push(relativePocPath);

          const execErr = execError as {
            message?: string;
            code?: number;
            stdout?: string;
            stderr?: string;
          };
          exitCode = execErr.code || 1;
          stdout = execErr.stdout || "";
          stderr = execErr.stderr || execErr.message || "";

          const attemptsRemaining = MAX_POC_ATTEMPTS - currentAttempts;

          // Check if this looks like a service unavailability issue
          const outputLower = (stdout + stderr).toLowerCase();
          const isServiceDown =
            stdout.includes("Service unavailable") ||
            stdout.includes("Connection refused") ||
            stderr.includes("ECONNREFUSED") ||
            stderr.includes("service unavailable") ||
            outputLower.includes("connection refused") ||
            outputLower.includes("econnrefused") ||
            outputLower.includes("service unavailable") ||
            outputLower.includes("connect etimedout") ||
            outputLower.includes("socket hang up") ||
            outputLower.includes("ehostunreach") ||
            outputLower.includes("network is unreachable") ||
            outputLower.includes("no route to host") ||
            outputLower.includes("connection reset") ||
            outputLower.includes("econnreset");

          return {
            success: false,
            pocPath: relativePocPath, // Include path even on failure - file still exists
            error: execErr.message,
            execution: {
              success: false,
              exitCode,
              stdout,
              stderr,
            },
            message: `POC execution FAILED (attempt ${currentAttempts}/${MAX_POC_ATTEMPTS})

**Error:** ${execErr.message || "Unknown error"}

**POC file saved at:** ${relativePocPath}
${
  isServiceDown
    ? "\n**NOTE:** Target service appears to be down/unavailable. POC may be valid but cannot be verified right now.\n"
    : ""
}
STDOUT:
\`\`\`
${stdout || "(none)"}
\`\`\`

STDERR:
\`\`\`
${stderr}
\`\`\`

${
  isServiceDown
    ? `**Service Unavailable - Options:**
- If you have strong evidence from EARLIER testing that confirms the vulnerability, you CAN call document_finding with pocPath: "${relativePocPath}"
- Otherwise, wait for service recovery or move to next target
- The POC file has been saved and can be manually verified later`
    : attemptsRemaining > 0
    ? `**Next Steps:**
- Analyze the error and create an improved POC
- Consider: syntax errors, missing dependencies, wrong assumptions
- ${attemptsRemaining} attempts remaining for this approach
- Call store_adaptation with worked=false and constraint_learned if you identified a blocker`
    : `**Max attempts reached for this approach.**
- Call store_adaptation with worked=false to record this dead end
- PIVOT to a different technique or vulnerability class
- Do NOT retry the same approach`
}`,
          };
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logger.error(`POC creation error: ${message}`);
        return {
          success: false,
          error: message,
          message: `Failed to create POC: ${message}

This is a system error, not an exploitation failure. Check:
- File permissions
- Disk space
- Script syntax`,
        };
      }
    },
  });

  return { create_poc, pocPaths };
}

export function createDocumentFindingTool(
  session: MetaTestingSessionInfo,
  logger: Logger,
  target: string,
  cvssOptions?: DocumentFindingCVSSOptions
) {
  const findingPaths: string[] = [];

  const document_finding = tool({
    description: `Document a confirmed vulnerability with evidence.

**Requirements:**
- POC must exist at the specified pocPath
- Include evidence from POC execution output
- Only call AFTER confirming exploitation via create_poc

This tool:
1. Validates POC exists
2. Checks for duplicate findings
3. Calculates CVSS 4.0 score (if enabled)
4. Saves finding JSON to session
5. Updates findings summary

**Call this when:**
- POC executed successfully AND
- Output confirms vulnerability exploitation AND
- Confidence > 80%`,
    inputSchema: DocumentFindingSchema,
    execute: async (
      finding: DocumentFindingInput
    ): Promise<DocumentFindingResult> => {
      logger.info(
        `Documenting finding: ${finding.title} [${finding.severity}]`
      );

      try {
        if (!existsSync(session.findingsPath)) {
          mkdirSync(session.findingsPath, { recursive: true });
        }

        const fullPocPath = join(session.rootPath, finding.pocPath);
        if (!existsSync(fullPocPath)) {
          return {
            success: false,
            error: "POC_NOT_FOUND",
            message: `POC not found at: ${finding.pocPath}

Create POC first using create_poc tool, then call document_finding.`,
          };
        }

        // Check for duplicates
        const existingFindings = loadExistingFindings(session.findingsPath);
        const isDuplicate = existingFindings.some(
          (f) =>
            (typeof f.title === "string" &&
              f.title.toLowerCase() === finding.title.toLowerCase()) ||
            (f.endpoint === finding.endpoint &&
              typeof f.description === "string" &&
              f.description
                .toLowerCase()
                .includes(finding.title.toLowerCase().split(" ")[0]))
        );

        if (isDuplicate) {
          logger.info(`Duplicate finding detected: ${finding.title}`);
          return {
            success: false,
            error: "DUPLICATE",
            message: `Duplicate finding - already documented.

Continue testing for OTHER vulnerabilities at different endpoints.`,
          };
        }

        const timestamp = new Date().toISOString();
        const id = nanoid(8);

        // Calculate CVSS 4.0 score if enabled
        let cvssData:
          | {
              score: number;
              severity: string;
              vectorString: string;
              metrics: CVSS4Metrics;
              scoreType: string;
              reasoning: string;
            }
          | undefined;

        // Default to true if not specified (per plan)
        const shouldScoreCVSS = cvssOptions?.enableCvssScoring !== false;

        if (shouldScoreCVSS) {
          try {
            const cvssModel = cvssOptions?.cvssModel || DEFAULT_CVSS_MODEL;
            const messages = cvssOptions?.getMessages?.() || [];

            logger.info(`Calculating CVSS 4.0 score for: ${finding.title}`);

            const cvssResult = await scoreFindingWithCVSS(
              {
                finding: {
                  title: finding.title,
                  description: finding.description,
                  impact: finding.impact,
                  evidence: finding.evidence,
                  endpoint: finding.endpoint,
                  vulnerabilityClass: (
                    finding as unknown as { vulnerabilityClass?: string }
                  ).vulnerabilityClass,
                  remediation: finding.remediation,
                },
                agentMessages: messages as Record<string, unknown>[],
              },
              cvssModel,
              cvssOptions?.authConfig
            );

            cvssData = {
              score: cvssResult.score,
              severity: cvssResult.severity,
              vectorString: cvssResult.vectorString,
              metrics: cvssResult.metrics,
              scoreType: cvssResult.scoreType,
              reasoning: cvssResult.reasoning,
            };

            logger.info(
              `CVSS 4.0 Score: ${cvssResult.score} (${cvssResult.severity}) - ${cvssResult.vectorString}`
            );
          } catch (cvssError) {
            // Non-blocking: log error and continue without CVSS
            logger.error(
              `CVSS scoring failed: ${
                cvssError instanceof Error
                  ? cvssError.message
                  : String(cvssError)
              }`
            );
          }
        }

        const findingWithMeta = {
          ...finding,
          id,
          timestamp,
          sessionId: session.id,
          target,
          ...(cvssData && {
            cvss: {
              score: cvssData.score,
              severity: cvssData.severity,
              vectorString: cvssData.vectorString,
              reasoning: cvssData.reasoning,
            },
          }),
        };

        const safeTitle = sanitizeFilename(finding.title);
        const filename = `${timestamp.split("T")[0]}-${safeTitle}.json`;
        const filepath = join(session.findingsPath, filename);

        writeFileSync(filepath, JSON.stringify(findingWithMeta, null, 2));
        findingPaths.push(filepath);

        const summaryPath = join(session.rootPath, "findings-summary.md");
        const cvssInfo = cvssData
          ? `\n  - CVSS 4.0: **${cvssData.score}** (${cvssData.severity})`
          : "";
        const summaryEntry = `\n- **[${finding.severity}]** ${finding.title}${cvssInfo}\n  - Endpoint: \`${finding.endpoint}\`\n  - POC: \`${finding.pocPath}\`\n  - Finding: \`findings/${filename}\`\n`;

        try {
          if (existsSync(summaryPath)) {
            appendFileSync(summaryPath, summaryEntry);
          } else {
            const header = `# Findings Summary

**Target:** ${target}
**Session:** ${session.id}
**Generated:** ${timestamp}

## Confirmed Vulnerabilities
${summaryEntry}`;
            writeFileSync(summaryPath, header);
          }
        } catch (e) {
          logger.error(`Failed to update findings summary: ${e}`);
        }

        logger.info(`Finding documented: ${filename}`);

        const cvssMessage = cvssData
          ? `\n- CVSS 4.0: **${cvssData.score}** (${cvssData.severity})\n- Vector: \`${cvssData.vectorString}\``
          : "";

        return {
          success: true,
          findingPath: filepath,
          message: `Finding documented successfully!

**[${finding.severity}]** ${finding.title}${cvssMessage}
- Saved to: findings/${filename}
- POC: ${finding.pocPath}

**Next Steps:**
1. Call store_adaptation with worked=true to record successful approach
2. Continue testing for additional vulnerabilities
3. Consider testing related endpoints or similar attack vectors`,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logger.error(`Document finding error: ${message}`);
        return {
          success: false,
          error: message,
          message: `Failed to document finding: ${message}`,
        };
      }
    },
  });

  return { document_finding, findingPaths };
}

function loadExistingFindings(findingsPath: string): Record<string, unknown>[] {
  if (!existsSync(findingsPath)) {
    return [];
  }

  try {
    const files = readdirSync(findingsPath).filter((f) => f.endsWith(".json"));
    return files
      .map((f) => {
        try {
          return JSON.parse(readFileSync(join(findingsPath, f), "utf-8"));
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}
