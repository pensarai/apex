import { tool } from "ai";
import { z } from "zod";
import { join, resolve } from "path";
import { homedir } from "os";
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "fs";
import type { FileAccessConfig } from "./types";
import { executeScript, executeScriptPersistent } from "./repl";
import type { SubAgentSession, AttackPlan, VerificationCriteria, Finding, PlanPhase, TieredIndicator } from "./types";
import { AttackPlanSchema, VerificationCriteriaSchema, FindingSchema, PlanPhaseSchema, TieredIndicatorSchema } from "./types";
import { createPentestTools } from "../tools";
import type { Session } from "../../session";
import { Memory } from "../../memory";
import { nanoid } from "nanoid";
import { runVerificationAgent } from "./verificationAgent";
import type { AIModel } from "../../ai";
import {
  createDelegateToAuthSubagentTool,
  createGetAuthSessionTool,
} from "../authenticationSubagent";

function toKebabCase(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")  // Replace non-alphanumeric with dashes
    .replace(/^-+|-+$/g, "")       // Remove leading/trailing dashes
    .replace(/-+/g, "-")           // Collapse multiple dashes
    .substring(0, 100);            // Limit length
}

/** Expand ~ to home directory */
function expandPath(p: string): string {
  if (p.startsWith("~/")) {
    return join(homedir(), p.slice(2));
  }
  if (p === "~") {
    return homedir();
  }
  return p;
}

function isPathAllowed(
  filePath: string,
  config: FileAccessConfig
): { allowed: boolean; reason?: string } {
  const resolved = resolve(expandPath(filePath));

  // Blocked paths take precedence
  for (const blocked of config.blockedPaths) {
    const normalizedBlocked = resolve(expandPath(blocked));
    if (resolved.startsWith(normalizedBlocked + "/") || resolved === normalizedBlocked) {
      return { allowed: false, reason: `Access to '${blocked}' is blocked` };
    }
  }

  // Must be within an allowed directory
  for (const allowed of config.allowedPaths) {
    const normalizedAllowed = resolve(expandPath(allowed));
    if (resolved.startsWith(normalizedAllowed + "/") || resolved === normalizedAllowed) {
      return { allowed: true };
    }
  }

  return { allowed: false, reason: "Path is outside allowed directories" };
}

export function createInitAgentTools(
  subagentSession: SubAgentSession,
  session: Session.SessionInfo,
  model: AIModel,
  abortSignal?: AbortSignal,
  fileAccessConfig?: FileAccessConfig
) {
  const { id, config, rootPath, planPath, verificationPath } = subagentSession;

  const read_file = tool({
    description: "Read a file from the filesystem",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
    }),
    execute: async ({ path }) => {
      if (fileAccessConfig) {
        const check = isPathAllowed(path, fileAccessConfig);
        if (!check.allowed) {
          return { success: false, error: `SANDBOX: ${check.reason}` };
        }
      }
      try {
        const content = readFileSync(path, "utf-8");
        return { success: true, content };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const search_code = tool({
    description: "Search source code using grep pattern (whitebox mode only)",
    inputSchema: z.object({
      pattern: z.string().describe("Regex pattern to search for"),
      path: z.string().optional().describe("Directory to search in"),
      filePattern: z.string().optional().describe("File glob pattern, e.g. *.ts"),
    }),
    execute: async ({ pattern, path, filePattern }) => {
      if (!config.whiteboxMode) {
        return { success: false, error: "Code search only available in whitebox mode" };
      }
      const searchPath = path || config.sourceCodePath || ".";
      const glob = filePattern || "**/*";
      try {
        const proc = Bun.spawn(
          ["rg", "--json", pattern, "-g", glob, searchPath],
          { stdout: "pipe", stderr: "pipe" }
        );
        const stdout = await new Response(proc.stdout).text();
        const matches = stdout
          .split("\n")
          .filter((l) => l.trim())
          .map((l) => {
            try {
              return JSON.parse(l);
            } catch {
              return null;
            }
          })
          .filter((m) => m?.type === "match")
          .slice(0, 50);
        return { success: true, matches };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const http_request = tool({
    description: "Make an HTTP request to probe the endpoint",
    inputSchema: z.object({
      url: z.string().describe("URL to request"),
      method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]).default("GET"),
      headers: z.record(z.string(), z.string()).optional(),
      body: z.string().optional(),
    }),
    execute: async ({ url, method, headers, body }) => {
      try {
        const response = await fetch(url, {
          method,
          headers,
          body: body || undefined,
        });
        const text = await response.text();
        return {
          success: true,
          status: response.status,
          headers: Object.fromEntries(response.headers.entries()),
          body: text.slice(0, 5000),
        };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const write_plan = tool({
    description: "Write the attack plan for this sub-agent",
    inputSchema: z.object({
      summary: z.string().describe("Summary of the attack approach"),
      phases: z.array(PlanPhaseSchema).describe("Attack phases"),
      contextGathered: z.record(z.string(), z.any()).optional().describe("Context gathered during init"),
    }),
    execute: async ({ summary, phases, contextGathered }) => {
      const plan: AttackPlan = {
        subagentId: id,
        endpoint: config.endpoint,
        vulnerabilityClass: config.vulnerabilityClass,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        summary,
        phases,
        contextGathered,
        notes: [],
      };
      writeFileSync(planPath, JSON.stringify(plan, null, 2));
      return { success: true, planPath };
    },
  });

  const write_verification_criteria = tool({
    description: `Write TIERED verification criteria for validating findings. Prioritize high-signal indicators:
- high: Proves exploitation (data exfil, command output, unauthorized access)
- medium: Strong evidence (timing delays, boolean differences)
- low: Detection only (error messages) - use sparingly

You can provide indicators as strings (defaults to medium tier) or as objects with tier specified.`,
    inputSchema: z.object({
      successIndicators: z.array(
        z.union([
          z.string(),
          z.object({
            indicator: z.string().describe("The indicator string to match"),
            tier: z.enum(["high", "medium", "low"]).describe("Signal tier: high proves exploitation, medium is strong evidence, low is detection only"),
          }),
        ])
      ).describe("Tiered indicators that confirm vulnerability. Prioritize high-signal indicators."),
      failureIndicators: z.array(z.string()).describe("Indicators that rule out vulnerability"),
      verificationSteps: z.array(
        z.object({
          description: z.string(),
          expectedOutcome: z.string(),
          method: z.enum(["response_contains", "status_code", "timing", "script", "manual"]),
          value: z.string().optional(),
        })
      ).describe("Steps to verify a finding"),
      minimumConfidence: z.number().optional().describe("Minimum confidence threshold (0-100)"),
    }),
    execute: async ({ successIndicators, failureIndicators, verificationSteps, minimumConfidence }) => {
      // Normalize indicators to tiered format
      const normalizedIndicators: TieredIndicator[] = successIndicators.map(ind => {
        if (typeof ind === "string") {
          return { indicator: ind, tier: "medium" as const };
        }
        return ind;
      });

      const criteria: VerificationCriteria = {
        subagentId: id,
        vulnerabilityClass: config.vulnerabilityClass,
        createdAt: new Date().toISOString(),
        successIndicators: normalizedIndicators,
        failureIndicators,
        verificationSteps,
        minimumConfidence: minimumConfidence || 80,
      };
      writeFileSync(verificationPath, JSON.stringify(criteria, null, 2));
      return { success: true, verificationPath };
    },
  });

  const complete_init = tool({
    description: "Signal that initialization is complete. Call after writing plan and verification criteria.",
    inputSchema: z.object({
      summary: z.string().describe("Summary of init phase findings"),
    }),
    execute: async ({ summary }) => {
      return { success: true, complete: true, summary };
    },
  });

  // Create auth tools
  const delegate_to_auth_subagent = createDelegateToAuthSubagentTool({
    session,
    model,
    abortSignal,
  });
  const get_auth_session = createGetAuthSessionTool(session);

  return {
    read_file,
    search_code,
    http_request,
    write_plan,
    write_verification_criteria,
    complete_init,
    delegate_to_auth_subagent,
    get_auth_session,
  };
}

function logToFile(logsPath: string, message: string): void {
  const timestamp = new Date().toISOString();
  const logEntry = `${timestamp} - ${message}\n`;
  try {
    appendFileSync(join(logsPath, "attack.log"), logEntry, "utf8");
  } catch {}
}

export function createAttackAgentTools(
  subagentSession: SubAgentSession,
  session: Session.SessionInfo,
  workspace: string,
  model: AIModel,
  abortSignal?: AbortSignal,
  toolOverride?: {
    execute_command?: (opts: any) => Promise<any>;
  },
  fileAccessConfig?: FileAccessConfig
) {
  const { id, config, rootPath, planPath, verificationPath, findingsPath, scriptsPath, logsPath } = subagentSession;

  const pentestTools = createPentestTools(session, undefined, toolOverride);
  const {
    execute_command,
    http_request: pentest_http_request,
    fuzz_endpoint,
    mutate_payload,
    smart_enumerate,
    cve_lookup,
  } = pentestTools;

  const read_file = tool({
    description: "Read a file from the filesystem",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
    }),
    execute: async ({ path }) => {
      if (fileAccessConfig) {
        const check = isPathAllowed(path, fileAccessConfig);
        if (!check.allowed) {
          return { success: false, error: `SANDBOX: ${check.reason}` };
        }
      }
      try {
        const content = readFileSync(path, "utf-8");
        return { success: true, content };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const write_file = tool({
    description: "Write content to a file",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
      content: z.string().describe("Content to write"),
    }),
    execute: async ({ path, content }) => {
      if (fileAccessConfig) {
        const check = isPathAllowed(path, fileAccessConfig);
        if (!check.allowed) {
          return { success: false, error: `SANDBOX: ${check.reason}` };
        }
      }
      try {
        const dir = path.substring(0, path.lastIndexOf("/"));
        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true });
        }
        writeFileSync(path, content);
        return { success: true, path };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const append_file = tool({
    description: "Append content to a file",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
      content: z.string().describe("Content to append"),
    }),
    execute: async ({ path, content }) => {
      if (fileAccessConfig) {
        const check = isPathAllowed(path, fileAccessConfig);
        if (!check.allowed) {
          return { success: false, error: `SANDBOX: ${check.reason}` };
        }
      }
      try {
        appendFileSync(path, content);
        return { success: true, path };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const search_code = tool({
    description: "Search source code (whitebox mode only)",
    inputSchema: z.object({
      pattern: z.string().describe("Regex pattern to search"),
      path: z.string().optional(),
      filePattern: z.string().optional(),
    }),
    execute: async ({ pattern, path, filePattern }) => {
      if (!config.whiteboxMode) {
        return { success: false, error: "Code search only available in whitebox mode" };
      }
      const searchPath = path || config.sourceCodePath || ".";
      const glob = filePattern || "**/*";
      try {
        const proc = Bun.spawn(
          ["rg", "--json", pattern, "-g", glob, searchPath],
          { stdout: "pipe", stderr: "pipe" }
        );
        const stdout = await new Response(proc.stdout).text();
        const matches = stdout
          .split("\n")
          .filter((l) => l.trim())
          .map((l) => {
            try {
              return JSON.parse(l);
            } catch {
              return null;
            }
          })
          .filter((m) => m?.type === "match")
          .slice(0, 50);
        return { success: true, matches };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const read_plan = tool({
    description: "Read the current attack plan",
    inputSchema: z.object({}),
    execute: async () => {
      try {
        const plan = JSON.parse(readFileSync(planPath, "utf-8")) as AttackPlan;
        return { success: true, plan };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const append_plan = tool({
    description: "Append notes or update phases in the attack plan",
    inputSchema: z.object({
      note: z.string().optional().describe("Note to append"),
      phaseUpdate: z
        .object({
          phaseName: z.string(),
          completed: z.boolean().optional(),
          notes: z.string().optional(),
        })
        .optional(),
    }),
    execute: async ({ note, phaseUpdate }) => {
      try {
        const plan = JSON.parse(readFileSync(planPath, "utf-8")) as AttackPlan;
        if (note) {
          plan.notes.push(`[${new Date().toISOString()}] ${note}`);
        }
        if (phaseUpdate) {
          const phase = plan.phases.find((p) => p.name === phaseUpdate.phaseName);
          if (phase) {
            if (phaseUpdate.completed !== undefined) phase.completed = phaseUpdate.completed;
            if (phaseUpdate.notes) phase.notes = phaseUpdate.notes;
          }
        }
        plan.updatedAt = new Date().toISOString();
        writeFileSync(planPath, JSON.stringify(plan, null, 2));
        return { success: true };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const execute_script = tool({
    description: `Execute a bun (TypeScript) or python script. Use this to write custom tools, exploits, or testing scripts.
The script will be saved to the scripts directory and executed. Output is captured.`,
    inputSchema: z.object({
      name: z.string().describe("Name for the script"),
      language: z.enum(["bun", "python"]).describe("Script language"),
      code: z.string().describe("Script code to execute"),
      timeout: z.number().optional().describe("Timeout in ms (default 60000)"),
      saveToMemory: z.boolean().optional().describe("Save script to workspace memory for reuse"),
      description: z.string().optional().describe("Description if saving to memory"),
      tags: z.array(z.string()).optional().describe("Tags if saving to memory"),
    }),
    execute: async ({ name, language, code, timeout, saveToMemory, description, tags }) => {
      const result = await executeScriptPersistent({
        language,
        code,
        timeout,
        scriptName: name,
        persistDir: scriptsPath,
        workingDir: rootPath,
      });

      if (saveToMemory && result.success && description) {
        try {
          await Memory.storeTool(workspace, {
            name,
            code,
            language,
            description,
            tags: tags || [],
            createdAt: new Date().toISOString(),
            usageCount: 1,
          });
        } catch {}
      }

      return result;
    },
  });

  const get_memory_tool = tool({
    description: "Retrieve a reusable tool from workspace memory",
    inputSchema: z.object({
      name: z.string().describe("Tool name"),
    }),
    execute: async ({ name }) => {
      const tool = await Memory.getTool(workspace, name);
      if (tool) {
        await Memory.incrementToolUsage(workspace, name);
        return { success: true, tool };
      }
      return { success: false, error: "Tool not found" };
    },
  });

  const search_memory = tool({
    description: "Search workspace memory for tools, techniques, or findings",
    inputSchema: z.object({
      query: z.string().describe("Search query"),
      types: z.array(z.enum(["tool", "technique", "finding"])).optional(),
      limit: z.number().optional(),
    }),
    execute: async ({ query, types, limit }) => {
      const results = await Memory.search(workspace, query, { types, limit });
      return { success: true, results };
    },
  });

  const read_verification_criteria = tool({
    description: "Read the verification criteria for this sub-agent",
    inputSchema: z.object({}),
    execute: async () => {
      try {
        const criteria = JSON.parse(readFileSync(verificationPath, "utf-8")) as VerificationCriteria;
        return { success: true, criteria };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const verify_finding = tool({
    description: `Verify a potential finding using the verification agent.

The verification agent will independently evaluate your evidence and provide:
- Whether the finding passes verification
- What evidence gaps exist
- Specific suggestions for strengthening the proof
- Actionable retry guidance if verification fails

IMPORTANT: If verification fails, use the feedback to adjust your approach and retry (up to 3 attempts).`,
    inputSchema: z.object({
      evidence: z.string().describe("All evidence collected for this finding"),
      confidence: z.number().min(0).max(100).describe("Your confidence level 0-100"),
    }),
    execute: async ({ evidence, confidence }) => {
      // Read verification criteria
      if (!existsSync(verificationPath)) {
        return {
          passed: false,
          verificationQuality: "failed",
          reason: "No verification criteria found. Call write_verification_criteria first.",
          gaps: ["No verification criteria defined"],
          suggestions: ["Create verification criteria before attempting to verify findings"],
          retryGuidance: "Create verification criteria by calling write_verification_criteria first.",
          matchedIndicators: [],
        };
      }

      let criteria: VerificationCriteria;
      try {
        criteria = JSON.parse(readFileSync(verificationPath, "utf-8"));
      } catch (error: any) {
        return {
          passed: false,
          verificationQuality: "failed",
          reason: `Failed to read verification criteria: ${error.message}`,
          gaps: ["Verification criteria file is invalid"],
          suggestions: ["Recreate verification criteria"],
          retryGuidance: "The verification criteria file is corrupted. Call write_verification_criteria to recreate it.",
          matchedIndicators: [],
        };
      }

      // Run verification agent
      try {
        const result = await runVerificationAgent({
          evidence,
          confidence,
          criteria,
          endpoint: config.endpoint,
          vulnerabilityClass: config.vulnerabilityClass,
          model,
          abortSignal,
        });

        // Log verification attempt
        logToFile(logsPath, `[VERIFY] Attempt with confidence ${confidence}%: ${result.passed ? "PASSED" : "FAILED"}`);
        logToFile(logsPath, `[VERIFY] Quality: ${result.verificationQuality}`);
        if (!result.passed) {
          logToFile(logsPath, `[VERIFY] Gaps: ${result.gaps.join(", ")}`);
          logToFile(logsPath, `[VERIFY] Guidance: ${result.retryGuidance}`);
        }

        return result;
      } catch (error: any) {
        logToFile(logsPath, `[VERIFY] Error: ${error.message}`);
        return {
          passed: false,
          verificationQuality: "failed",
          reason: `Verification agent error: ${error.message}`,
          gaps: ["Verification agent encountered an error"],
          suggestions: ["Retry verification"],
          retryGuidance: "The verification agent encountered an error. Try calling verify_finding again.",
          matchedIndicators: [],
        };
      }
    },
  });

  const document_finding = tool({
    description: "Document a verified vulnerability finding with POC",
    inputSchema: z.object({
      title: z.string(),
      severity: z.enum(["critical", "high", "medium", "low", "info"]),
      description: z.string(),
      impact: z.string(),
      evidence: z.string(),
      pocPath: z.string().optional(),
      remediation: z.string(),
    }),
    execute: async ({ title, severity, description, impact, evidence, pocPath, remediation }) => {
      const findingId = nanoid(8);
      const finding: Finding = {
        id: findingId,
        subagentId: id,
        title,
        severity,
        vulnerabilityClass: config.vulnerabilityClass,
        endpoint: config.endpoint,
        description,
        impact,
        evidence,
        pocPath,
        remediation,
        verificationPassed: true,
        createdAt: new Date().toISOString(),
      };

      // Generate kebab-case filename from title
      const kebabTitle = toKebabCase(title);
      const filename = `${kebabTitle}.json`;

      // Write to subagent findings directory
      const findingPath = join(findingsPath, filename);
      writeFileSync(findingPath, JSON.stringify(finding, null, 2));

      // Copy to session root findings directory
      const sessionFindingPath = join(session.findingsPath, filename);
      writeFileSync(sessionFindingPath, JSON.stringify(finding, null, 2));

      try {
        await Memory.storeFinding(workspace, {
          id: findingId,
          title,
          vulnerabilityClass: config.vulnerabilityClass,
          endpoint: config.endpoint,
          severity,
          technique: description.slice(0, 100),
          createdAt: finding.createdAt,
        });
      } catch {}

      return { success: true, findingId, findingPath };
    },
  });

  const complete_attack = tool({
    description: "Signal that attack phase is complete",
    inputSchema: z.object({
      summary: z.string().describe("Summary of attack phase results"),
      findingsCount: z.number().describe("Number of findings documented"),
    }),
    execute: async ({ summary, findingsCount }) => {
      return { success: true, complete: true, summary, findingsCount };
    },
  });

  // Create auth tools
  const delegate_to_auth_subagent = createDelegateToAuthSubagentTool({
    session,
    model,
    abortSignal,
  });
  const get_auth_session = createGetAuthSessionTool(session);

  return {
    execute_command,
    http_request: pentest_http_request,
    fuzz_endpoint,
    mutate_payload,
    smart_enumerate,
    cve_lookup,
    read_file,
    write_file,
    append_file,
    search_code,
    read_plan,
    append_plan,
    execute_script,
    get_memory_tool,
    search_memory,
    read_verification_criteria,
    verify_finding,
    document_finding,
    complete_attack,
    delegate_to_auth_subagent,
    get_auth_session,
  };
}
