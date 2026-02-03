import { streamResponse, type AIModel } from "../../ai";
import { hasToolCall } from "ai";
import type {
  SubAgentSession,
  AttackAgentResult,
  Finding,
  AttackPlan,
  VerificationCriteria,
  FileAccessConfig,
} from "./types";
import { createAttackAgentTools } from "./tools";
import type { Session } from "../../session";
import { existsSync, readFileSync, readdirSync, appendFileSync } from "fs";
import { join } from "path";
import { Messages } from "../../messages";
import { listGuidanceFiles } from "./guidance";

const ATTACK_SYSTEM_PROMPT = `You are a security testing attack agent. Your job is to execute the attack plan and find vulnerabilities.

Target: {endpoint}
Vulnerability Class: {vulnerabilityClass}

## Vulnerability Testing Reference Guides

You have access to comprehensive testing methodology guides in your workspace:

\`\`\`
{guidanceFiles}
\`\`\`

**HOW TO USE THESE GUIDES:**

1. **Before starting each attack phase** - Use \`read_file\` to read the relevant guidance file
2. **When a technique fails** - Consult the guide for alternative payloads and bypass techniques
3. **When testing filter evasion** - Reference the WAF/filter bypass section
4. **When verifying findings** - Use the verification checklist in the guide

These guides contain:
- Multiple injection context patterns (value injection, clause injection, etc.)
- Database/framework-specific payloads
- WAF and filter bypass techniques
- Polyglot payloads for multi-context testing
- Step-by-step exploitation workflows

**CRITICAL:** Do not rely solely on common payloads. The guides document edge cases
and alternative patterns that may apply to your target. For example, SQL injection
can occur at the value level (\`WHERE name='$input'\`) OR at the clause level
(\`WHERE $input\`) - different patterns require different payloads.

## Your Tools

You have access to:
- **execute_command**: Run shell commands (nmap, curl, etc.)
- **http_request**: Make HTTP requests with full control
- **fuzz_endpoint**: Fuzz parameters for IDOR
- **mutate_payload**: Generate encoding variants for filter bypass
- **cve_lookup**: Search for known CVEs
- **execute_script**: Write and run custom bun/python scripts (KEY TOOL)
- **read_file/write_file/append_file**: File operations
- **search_code**: Search source code (whitebox only)
- **read_plan/append_plan**: Access and update your attack plan
- **search_memory/get_memory_tool**: Access workspace memory for reusable tools
- **verify_finding**: Validate findings against criteria
- **document_finding**: Record confirmed vulnerabilities
- **delegate_to_auth_subagent**: Authenticate with target (complex auth flows)
- **get_auth_session**: Load existing authenticated session

## Attack Approach

1. Read the plan and verification criteria
2. Execute each phase systematically
3. Use execute_script to write custom tools when needed
4. When you find something, verify it against criteria before documenting
5. Update the plan with your progress and findings

## Script Writing

The execute_script tool is powerful. Use it to:
- Write multi-step exploits
- Create parallel request scripts
- Build custom payload generators
- Parse complex responses
- Implement timing attacks

Example bun script:
\`\`\`typescript
const response = await fetch("http://target/api", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ user: "admin'--" })
});
const text = await response.text();
console.log(text);
if (text.includes("error in your SQL")) {
  console.log("VULNERABLE: SQL Injection confirmed");
  process.exit(0);
}
process.exit(1);
\`\`\`

## Verification

Before documenting any finding:
1. Call read_verification_criteria to understand success/failure indicators
2. Call verify_finding with your evidence and confidence
3. Only document if verification passes

**When verification fails:**

The verify_finding tool returns detailed feedback:
- \`gaps\`: What evidence is missing
- \`suggestions\`: Specific techniques to try
- \`retryGuidance\`: Actionable next steps

**You MUST use this feedback to retry (up to 3 attempts):**

1. Read the gaps and suggestions carefully
2. Execute the suggested techniques to collect stronger evidence
3. Call verify_finding again with the new evidence
4. Repeat until verification passes or you've exhausted options

**Example flow:**
\`\`\`
verify_finding(evidence="500 error on search param", confidence=60)
→ Failed: gaps=["No data extraction proof"], suggestions=["Try UNION SELECT to extract data"]

# Execute suggested technique
execute_script(script="...UNION SELECT...")

verify_finding(evidence="UNION SELECT returned admin table: id=1,email=admin@...", confidence=90)
→ Passed: verificationQuality="strong"

document_finding(...)
\`\`\`

**If verification keeps failing:**
After 3 attempts, if you have detection-level evidence (errors, timing anomalies), document the finding with:
- Lower severity (info/low)
- Clear notes that full exploitation was not achieved
- The detection evidence you collected

## Authentication

If the target requires authentication:
1. Check if session-info.json exists (use get_auth_session tool)
2. If not authenticated, use delegate_to_auth_subagent to authenticate
3. Use returned sessionCookie/headers in http_request calls

Session credentials may be pre-configured. Call delegate_to_auth_subagent
without explicit credentials to use session defaults.

## IMPORTANT: Document Findings Incrementally

**DO NOT wait until the end to document findings.** As soon as you have verified evidence of a vulnerability:
1. Call verify_finding with your evidence
2. If verification passes, immediately call document_finding
3. Then continue testing for additional vulnerabilities or stronger proof

**For injection vulnerabilities specifically:**
- If you have boolean-based evidence (1=1 vs 1=2 shows different results), that is SUFFICIENT to document as a confirmed SQLi
- Document the boolean-based finding first, then continue trying UNION SELECT for data extraction
- If UNION fails, you still have the boolean-based finding documented

**Time awareness:** You have limited time. Don't spend too long trying to perfect one technique if you already have proof of the vulnerability. Document what you have, then try to improve it.

Call complete_attack when testing is done.`;

function logToFile(logsPath: string, message: string): void {
  const timestamp = new Date().toISOString();
  const logEntry = `${timestamp} - ${message}\n`;
  try {
    appendFileSync(join(logsPath, "attack.log"), logEntry, "utf8");
  } catch {}
}

export async function runAttackAgent(
  subagentSession: SubAgentSession,
  session: Session.SessionInfo,
  workspace: string,
  model: AIModel,
  abortSignal?: AbortSignal,
  toolOverride?: {
    execute_command?: (opts: any) => Promise<any>;
  },
  fileAccessConfig?: FileAccessConfig,
  onStepFinish?: (step: {
    text?: string;
    toolCalls?: Array<{ toolCallId: string; toolName: string; args: unknown }>;
    toolResults?: Array<{
      toolCallId: string;
      toolName: string;
      result: unknown;
    }>;
  }) => void,
  onChunk?: (chunk: {
    type: "text-delta" | "tool-call" | "tool-result";
    text?: string;
    toolCallId?: string;
    toolName?: string;
    args?: unknown;
    result?: unknown;
  }) => void,
): Promise<AttackAgentResult> {
  const {
    config,
    planPath,
    verificationPath,
    findingsPath,
    logsPath,
    rootPath,
  } = subagentSession;

  logToFile(
    logsPath,
    `[INFO] Starting attack phase for endpoint: ${config.endpoint}`,
  );
  logToFile(
    logsPath,
    `[INFO] Vulnerability class: ${config.vulnerabilityClass}`,
  );

  const tools = createAttackAgentTools(
    subagentSession,
    session,
    workspace,
    model,
    abortSignal,
    toolOverride,
    fileAccessConfig,
  );

  const guidanceFileList = listGuidanceFiles(subagentSession.guidancePath);
  const guidanceFilesStr =
    guidanceFileList.length > 0
      ? guidanceFileList.join("\n")
      : "No guidance files available";

  const systemPrompt = ATTACK_SYSTEM_PROMPT.replace(
    "{endpoint}",
    config.endpoint,
  )
    .replace("{vulnerabilityClass}", config.vulnerabilityClass)
    .replace("{guidanceFiles}", guidanceFilesStr);

  let plan: AttackPlan | null = null;
  let verificationCriteria: VerificationCriteria | null = null;

  if (existsSync(planPath)) {
    plan = JSON.parse(readFileSync(planPath, "utf-8"));
    logToFile(
      logsPath,
      `[INFO] Loaded attack plan with ${plan?.phases?.length || 0} phases`,
    );
  }
  if (existsSync(verificationPath)) {
    verificationCriteria = JSON.parse(readFileSync(verificationPath, "utf-8"));
    logToFile(logsPath, `[INFO] Loaded verification criteria`);
  }

  let userPrompt = `Execute the attack plan for ${config.endpoint} targeting ${config.vulnerabilityClass}.`;

  if (plan) {
    userPrompt += `\n\n## Attack Plan\n${JSON.stringify(plan, null, 2)}`;
  }

  if (verificationCriteria) {
    userPrompt += `\n\n## Verification Criteria\n${JSON.stringify(verificationCriteria, null, 2)}`;
  }

  if (config.context) {
    userPrompt += `\n\n## Additional Context\n${JSON.stringify(config.context, null, 2)}`;
  }

  userPrompt += `\n\nExecute the plan phases, verify any findings, and document confirmed vulnerabilities.
Call complete_attack when done.`;

  try {
    const streamResult = streamResponse({
      prompt: userPrompt,
      system: systemPrompt,
      model,
      tools,
      stopWhen: hasToolCall("complete_attack"),
      abortSignal,
      silent: true,
      onStepFinish: (step) => {
        for (const toolCall of step.toolCalls) {
          logToFile(logsPath, `[INFO] Tool call: ${toolCall.toolName}`);
        }
        for (const toolResult of step.toolResults) {
          logToFile(
            logsPath,
            `[INFO] Tool result: ${toolResult.toolName} - completed`,
          );
        }
        // Forward step to UI callback for real-time streaming
        onStepFinish?.({
          text: step.text,
          toolCalls: step.toolCalls.map((tc) => ({
            toolCallId: tc.toolCallId,
            toolName: tc.toolName,
            args: (tc as any).input || (tc as any).args,
          })),
          toolResults: step.toolResults.map((tr) => ({
            toolCallId: tr.toolCallId,
            toolName: tr.toolName,
            result: (tr as any).output || (tr as any).result,
          })),
        });
      },
    });

    let calledCompleteAttack = false;
    for await (const chunk of streamResult.fullStream) {
      if (chunk.type === "error") {
        throw (chunk as any).error;
      }
      // Check if complete_attack was called
      if (chunk.type === "tool-call" && chunk.toolName === "complete_attack") {
        calledCompleteAttack = true;
      }
      // Forward chunk for real-time UI streaming
      if (onChunk) {
        if (chunk.type === "text-delta") {
          onChunk({ type: "text-delta", text: (chunk as any).text });
        } else if (chunk.type === "tool-call") {
          const tc = chunk as any;
          onChunk({
            type: "tool-call",
            toolCallId: tc.toolCallId,
            toolName: tc.toolName,
            // AI SDK uses 'input' not 'args' for tool-call chunks
            args: tc.input ?? tc.args,
          });
        } else if (chunk.type === "tool-result") {
          const tr = chunk as any;
          onChunk({
            type: "tool-result",
            toolCallId: tr.toolCallId,
            toolName: tr.toolName,
            // AI SDK uses 'output' not 'result' for tool-result chunks
            result: tr.output ?? tr.result,
          });
        }
      }
    }

    // Capture and save messages
    try {
      const response = await streamResult.response;
      const messages = response.messages;
      Messages.saveSubagentPhaseMessages(rootPath, "attack", messages);
      logToFile(
        logsPath,
        `[INFO] Saved ${messages.length} messages to attack-messages.json`,
      );
    } catch (msgError: any) {
      logToFile(
        logsPath,
        `[WARN] Failed to save messages: ${msgError.message}`,
      );
    }

    const findings: Finding[] = [];
    if (existsSync(findingsPath)) {
      const files = readdirSync(findingsPath).filter((f) =>
        f.endsWith(".json"),
      );
      for (const file of files) {
        try {
          const finding = JSON.parse(
            readFileSync(join(findingsPath, file), "utf-8"),
          );
          findings.push(finding);
        } catch {}
      }
    }

    // Check if stream ended due to abort signal (timeout) vs complete_attack
    const wasAborted = abortSignal?.aborted && !calledCompleteAttack;
    if (wasAborted) {
      logToFile(
        logsPath,
        `[WARN] Attack phase interrupted by abort signal (likely timeout)`,
      );
      logToFile(
        logsPath,
        `[INFO] Findings count before interruption: ${findings.length}`,
      );
      return {
        success: false,
        findings,
        summary: `Attack phase interrupted (timeout/abort). Found ${findings.length} vulnerabilities before interruption.`,
        error: "Attack phase interrupted by timeout or abort signal",
      };
    }

    logToFile(logsPath, `[INFO] Attack phase completed successfully`);
    logToFile(logsPath, `[INFO] Findings count: ${findings.length}`);

    return {
      success: true,
      findings,
      summary: `Attack phase complete. Found ${findings.length} vulnerabilities.`,
    };
  } catch (error: any) {
    logToFile(logsPath, `[ERROR] Attack phase failed: ${error.message}`);

    const findings: Finding[] = [];
    if (existsSync(findingsPath)) {
      const files = readdirSync(findingsPath).filter((f) =>
        f.endsWith(".json"),
      );
      for (const file of files) {
        try {
          const finding = JSON.parse(
            readFileSync(join(findingsPath, file), "utf-8"),
          );
          findings.push(finding);
        } catch {}
      }
    }

    logToFile(
      logsPath,
      `[INFO] Findings count before error: ${findings.length}`,
    );

    return {
      success: false,
      findings,
      summary: `Attack phase terminated with error: ${error.message}`,
      error: error.message,
    };
  }
}
