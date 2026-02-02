import { streamResponse, type AIModel } from "../../ai";
import { hasToolCall } from "ai";
import type {
  SubAgentSession,
  InitAgentResult,
  AttackPlan,
  VerificationCriteria,
  FileAccessConfig,
} from "./types";
import { createInitAgentTools } from "./tools";
import { existsSync, readFileSync, appendFileSync } from "fs";
import { join } from "path";
import { Messages } from "../../messages";
import { buildVerificationPrompt } from "./verificationGuidance";
import { listGuidanceFiles } from "./guidance";
import type { Session } from "../../session";

const INIT_SYSTEM_PROMPT = `You are a security testing initialization agent. Your job is to:

1. Gather context about the target endpoint
2. Analyze the attack surface and understand the application
3. Create a structured attack plan with phases
4. Define clear verification criteria for validating findings

You are testing for: {vulnerabilityClass}
Target endpoint: {endpoint}

## Vulnerability Testing Reference Guides

Comprehensive testing methodology guides are available in your workspace:

\`\`\`
{guidanceFiles}
\`\`\`

**When creating your attack plan:**
1. Use \`read_file\` to read the guidance file for {vulnerabilityClass}
2. Incorporate techniques from the guide into your plan phases
3. Include multiple injection patterns/contexts documented in the guide
4. Add bypass techniques from the guide to your testing approach

This ensures your plan covers edge cases and alternative attack vectors
that may be missed by generic testing approaches.

## Your Process

1. **Reconnaissance**: Probe the endpoint, understand its behavior, identify parameters
2. **Context Gathering**: If whitebox mode, search source code for relevant handlers
3. **Plan Creation**: Create a phased attack plan with specific techniques
4. **Verification Criteria**: Define what constitutes a successful exploit vs false positive

## Plan Structure

Your plan should have phases like:
- Recon: Initial probing and parameter discovery
- Fingerprinting: Identify technologies, frameworks, protections
- Testing: Specific vulnerability tests
- Exploitation: Confirmed exploit techniques
- Validation: Verify the finding is real

{verificationGuidance}

## Verification Requirements

Your verification criteria MUST:
1. Prioritize HIGH signal indicators that prove exploitation
2. Use MEDIUM signal indicators when HIGH signal isn't achievable
3. Use LOW signal indicators sparingly - they only detect potential, not exploitation
4. Include failure indicators to rule out false positives
5. Be specific, matchable strings for the verify_finding tool

When calling write_verification_criteria, specify the tier for each success indicator:
- tier: "high" - Proves exploitation (prioritize these)
- tier: "medium" - Strong evidence of vulnerability
- tier: "low" - Detection only, use sparingly

## Authentication

If the target requires authentication:
1. Check if session-info.json exists (use get_auth_session tool)
2. If not authenticated, use delegate_to_auth_subagent to authenticate
3. Use returned sessionCookie/headers in http_request calls

Session credentials may be pre-configured. Call delegate_to_auth_subagent
without explicit credentials to use session defaults.

Call complete_init when you have created both the plan and verification criteria.`;

function logToFile(logsPath: string, message: string): void {
  const timestamp = new Date().toISOString();
  const logEntry = `${timestamp} - ${message}\n`;
  try {
    appendFileSync(join(logsPath, "init.log"), logEntry, "utf8");
  } catch {}
}

export async function runInitAgent(
  subagentSession: SubAgentSession,
  session: Session.SessionInfo,
  model: AIModel,
  abortSignal?: AbortSignal,
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
): Promise<InitAgentResult> {
  const { config, planPath, verificationPath, logsPath, rootPath } =
    subagentSession;

  logToFile(
    logsPath,
    `[INFO] Starting init phase for endpoint: ${config.endpoint}`,
  );
  logToFile(
    logsPath,
    `[INFO] Vulnerability class: ${config.vulnerabilityClass}`,
  );
  logToFile(logsPath, `[INFO] Whitebox mode: ${config.whiteboxMode}`);

  const tools = createInitAgentTools(
    subagentSession,
    session,
    model,
    abortSignal,
    fileAccessConfig,
  );

  const guidanceFileList = listGuidanceFiles(subagentSession.guidancePath);
  const guidanceFilesStr =
    guidanceFileList.length > 0
      ? guidanceFileList.join("\n")
      : "No guidance files available";

  const verificationGuidance = buildVerificationPrompt(
    config.vulnerabilityClass,
  );
  const systemPrompt = INIT_SYSTEM_PROMPT.replace(
    /{vulnerabilityClass}/g,
    config.vulnerabilityClass,
  )
    .replace("{endpoint}", config.endpoint)
    .replace("{guidanceFiles}", guidanceFilesStr)
    .replace("{verificationGuidance}", verificationGuidance);

  let userPrompt = `Initialize testing for ${config.endpoint} targeting ${config.vulnerabilityClass} vulnerabilities.`;

  if (config.context) {
    userPrompt += `\n\nAdditional context provided:\n${JSON.stringify(config.context, null, 2)}`;
  }

  if (config.whiteboxMode && config.sourceCodePath) {
    userPrompt += `\n\nThis is a whitebox test. Source code is available at: ${config.sourceCodePath}
Use search_code to find relevant handlers, validation logic, and database queries.`;
  }

  userPrompt += `\n\nCreate a plan and verification criteria, then call complete_init.`;

  try {
    const streamResult = streamResponse({
      prompt: userPrompt,
      system: systemPrompt,
      model,
      tools,
      stopWhen: hasToolCall("complete_init"),
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

    for await (const chunk of streamResult.fullStream) {
      if (chunk.type === "error") {
        throw (chunk as any).error;
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
      Messages.saveSubagentPhaseMessages(rootPath, "init", messages);
      logToFile(
        logsPath,
        `[INFO] Saved ${messages.length} messages to init-messages.json`,
      );
    } catch (msgError: any) {
      logToFile(
        logsPath,
        `[WARN] Failed to save messages: ${msgError.message}`,
      );
    }

    let plan: AttackPlan | null = null;
    let verificationCriteria: VerificationCriteria | null = null;

    if (existsSync(planPath)) {
      plan = JSON.parse(readFileSync(planPath, "utf-8"));
    }
    if (existsSync(verificationPath)) {
      verificationCriteria = JSON.parse(
        readFileSync(verificationPath, "utf-8"),
      );
    }

    if (!plan || !verificationCriteria) {
      logToFile(
        logsPath,
        `[ERROR] Init agent did not create required artifacts`,
      );
      return {
        success: false,
        plan: plan || ({} as AttackPlan),
        verificationCriteria:
          verificationCriteria || ({} as VerificationCriteria),
        error: "Init agent did not create required artifacts",
      };
    }

    logToFile(logsPath, `[INFO] Init phase completed successfully`);
    logToFile(logsPath, `[INFO] Plan phases: ${plan.phases?.length || 0}`);
    return {
      success: true,
      plan,
      verificationCriteria,
    };
  } catch (error: any) {
    logToFile(logsPath, `[ERROR] Init phase failed: ${error.message}`);
    return {
      success: false,
      plan: {} as AttackPlan,
      verificationCriteria: {} as VerificationCriteria,
      error: error.message,
    };
  }
}
