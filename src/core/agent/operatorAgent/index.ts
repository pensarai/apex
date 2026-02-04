/**
 * OperatorAgent - Operator Mode Agent
 *
 * A single agent that collaborates with the pentester through approval gates.
 * Unlike SwarmMode, this runs one agent that waits for approval on risky actions.
 */

import { EventEmitter } from "events";
import { stepCountIs } from "ai";
import { appendFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import type { AIModel } from "../../ai";
import { streamResponse } from "../../ai/ai";
import { Session } from "../../session";
import {
  ApprovalGate,
  ApprovalBlockedError,
  ApprovalDeniedError,
  StageManager,
  inferStageFromDirective,
  type OperatorMode,
  type OperatorStage,
  type PermissionTier,
  type PendingApproval,
  type ActionHistoryEntry,
  type OperatorEvent,
  OPERATOR_STAGES,
} from "../../operator";
import { createPentestTools, ATTACK_KNOWLEDGE, isBackgroundTool } from "../tools";
import { taskManager } from "../taskManager";
import { createBrowserTools, disconnectMcpClient } from "../browserTools";
import { createPocTool } from "../metaTestingAgent/pocTools";
import { Logger } from "../logger";
import { inferVulnerabilityClasses } from "../orchestrator/prompts";
import type { DisplayMessage } from "../../../tui/components/agent-display";
import { runAuthenticationSubagent } from "../authenticationSubagent";
import { tool } from "ai";
import { z } from "zod";
import { getActiveToolNames } from "../../toolset";

/**
 * Cognitive testing loop for offensive stages (test/validate)
 * Borrowed from pentestagent's META_TESTING methodology
 */
const OFFENSIVE_COGNITIVE_LOOP = `
## Cognitive Testing Loop (Test/Validate Stages)

Every test action MUST follow this cycle:

### HYPOTHESIS (Before EVERY tool call)
HYPOTHESIS:
- Technique: [what I'm testing] (attempt N)
- Confidence: [0-100%] because [reasoning]
- Expected: if TRUE -> [outcome] | if FALSE -> [pivot plan]

### VALIDATION (After EVERY result)
VALIDATION:
- Outcome: [YES/NO + evidence]
- Constraint learned: [specific insight]
- Confidence: BEFORE [X%] -> AFTER [Y%]
- Decision: pivot (<50%) | iterate (50-80%) | exploit (>80%)

**Rules:**
- Pivot at <50% confidence - don't waste budget on dead ends
- Direct-first: What's the MINIMUM steps to demonstrate this vulnerability?
- Create POCs with create_poc to prove findings (supports bash, python, javascript)
`;

export type OperatorAgentStatus = "idle" | "running" | "waiting" | "paused" | "completed" | "failed";

/** Attack surface endpoint for resume context */
export interface AttackSurfaceEndpoint {
  method: string;
  path: string;
  status?: string;
  category?: string;
}

export interface OperatorAgentConfig {
  session: Session.SessionInfo;
  model: AIModel;
  initialMode?: OperatorMode;
  autoApproveTier?: PermissionTier;
  initialStage?: OperatorStage;
  /** Previous messages to restore on resume (for session continuity) */
  previousMessages?: DisplayMessage[];
  /** Attack surface endpoints discovered in previous session (for resume context) */
  previousAttackSurface?: AttackSurfaceEndpoint[];
  /** Callback for token usage updates (called after each step) */
  onTokenUsage?: (inputTokens: number, outputTokens: number) => void;
}

export interface OperatorAgentResult {
  findingsCount: number;
  pocPaths: string[];
  summary: string;
  error?: string;
}

/**
 * OperatorAgent class - single agent with approval gates
 */
export class OperatorAgent extends EventEmitter {
  private _status: OperatorAgentStatus = "idle";
  private config: OperatorAgentConfig;
  private abortController: AbortController | null = null;
  private messages: DisplayMessage[];
  private userDirectives: string[] = [];
  private findingsSummary: string = "";
  private logPath: string;
  private runId: string;
  private isResume: boolean = false;
  private attackSurface: AttackSurfaceEndpoint[] = [];
  // O(1) lookup for tool message indices by toolCallId (prevents O(n²) searches)
  private toolCallIdToIndex: Map<string, number> = new Map();

  // Operator components
  readonly approvalGate: ApprovalGate;
  readonly stageManager: StageManager;

  constructor(config: OperatorAgentConfig) {
    super();
    this.config = config;

    // Initialize messages (restore from previous session if resuming)
    this.messages = config.previousMessages ?? [];

    // Track if this is a resume (has previous messages loaded)
    this.isResume = !!(config.previousMessages && config.previousMessages.length > 0);

    // Store attack surface from previous session (for resume context)
    this.attackSurface = config.previousAttackSurface ?? [];

    // Initialize logging
    this.runId = `run_${Date.now()}`;
    const logsDir = join(config.session.rootPath, "logs");
    if (!existsSync(logsDir)) {
      mkdirSync(logsDir, { recursive: true });
    }
    this.logPath = join(logsDir, `operator_${this.runId}.jsonl`);
    this.log("session_start", {
      sessionId: config.session.id,
      target: config.session.targets[0],
      mode: config.initialMode || "manual",
      autoApproveTier: config.autoApproveTier || 2,
      model: config.model,
    });

    // Initialize approval gate with offensive stage tools for auto-approval in test/validate
    this.approvalGate = new ApprovalGate({
      mode: config.initialMode || "manual",
      autoApproveTier: config.autoApproveTier || 2,
      currentStage: config.initialStage || "setup",
      offensiveStageTools: ["test_parameter", "fuzz_endpoint", "create_poc"],
    });

    // Initialize stage manager
    this.stageManager = new StageManager(config.initialStage || "setup");

    // Forward approval gate events
    this.approvalGate.on("operator-event", (event: OperatorEvent) => {
      this.emit("operator-event", event);
      this.log("operator_event", event);
      if (event.type === "approval-needed") {
        this.setStatus("waiting");
      }
      if (event.type === "approval-resolved") {
        if (this._status === "waiting") {
          this.setStatus("running");
        }
      }
    });

    // Forward stage manager events
    this.stageManager.on("operator-event", (event: OperatorEvent) => {
      this.emit("operator-event", event);
      this.log("operator_event", event);
    });
  }

  /**
   * Log an event to the JSONL file
   */
  private log(type: string, data: any): void {
    const entry = {
      timestamp: new Date().toISOString(),
      runId: this.runId,
      type,
      ...data,
    };
    try {
      appendFileSync(this.logPath, JSON.stringify(entry) + "\n");
    } catch (e) {
      // Silently fail if logging fails
    }
  }

  get status(): OperatorAgentStatus {
    return this._status;
  }

  get mode(): OperatorMode {
    return this.approvalGate.getConfig().mode;
  }

  get currentStage(): OperatorStage {
    return this.stageManager.getCurrentStage();
  }

  get allMessages(): DisplayMessage[] {
    return [...this.messages];
  }

  get currentRunId(): string {
    return this.runId;
  }

  private setStatus(status: OperatorAgentStatus): void {
    const prevStatus = this._status;
    this._status = status;
    this.log("status_change", { from: prevStatus, to: status });
    this.emit("status-change", status);
  }

  private addMessage(message: DisplayMessage): void {
    const index = this.messages.length;
    this.messages.push(message);

    // Index tool messages by toolCallId for O(1) lookup
    const toolCallId = (message as any).toolCallId;
    if (message.role === "tool" && toolCallId) {
      this.toolCallIdToIndex.set(toolCallId, index);
    }

    this.log("message", {
      role: message.role,
      content: message.content,
      toolName: (message as any).toolName,
      toolCallId,
      args: (message as any).args,
    });
    this.emit("message", message);
  }

  private updateMessage(index: number, message: DisplayMessage): void {
    this.messages[index] = message;
    this.log("message_updated", {
      index,
      role: message.role,
      content: message.content,
      status: (message as any).status,
      result: (message as any).result,
    });
    this.emit("message-updated", { index, message });
  }

  /**
   * Add a streaming log to a tool message
   */
  private addToolLog(toolCallId: string, log: string): void {
    const msgIdx = this.toolCallIdToIndex.get(toolCallId);
    if (msgIdx === undefined) return;

    const existingMsg = this.messages[msgIdx];
    if (!existingMsg || existingMsg.role !== "tool") return;

    const currentLogs = existingMsg.logs || [];
    const updatedMsg = {
      ...existingMsg,
      logs: [...currentLogs, log],
    };
    this.updateMessage(msgIdx, updatedMsg);
  }

  /**
   * Change the operating mode
   */
  setMode(mode: OperatorMode): void {
    this.log("mode_change", { mode });
    this.approvalGate.updateConfig({ mode });
    this.emit("operator-event", { type: "mode-changed", mode });
  }

  /**
   * Change the auto-approve tier
   */
  setAutoApproveTier(tier: PermissionTier): void {
    this.log("tier_change", { tier });
    this.approvalGate.updateConfig({ autoApproveTier: tier });
  }

  /**
   * Transition to a new stage
   */
  setStage(stage: OperatorStage): void {
    this.stageManager.transitionTo(stage);
    // Sync stage with approval gate for stage-aware auto-approval
    this.approvalGate.updateConfig({ currentStage: stage });
  }

  /**
   * Get pending approvals
   */
  getPendingApprovals(): PendingApproval[] {
    return this.approvalGate.getPendingApprovals();
  }

  /**
   * Get action history
   */
  getActionHistory(): ActionHistoryEntry[] {
    return this.approvalGate.getActionHistory();
  }

  /**
   * Approve a pending action
   */
  approve(approvalId: string): void {
    const pending = this.approvalGate.getPendingApprovals().find(p => p.id === approvalId);
    this.log("action_approved", { approvalId, toolName: pending?.toolName, args: pending?.args });
    this.approvalGate.approve(approvalId);
  }

  /**
   * Deny a pending action
   */
  deny(approvalId: string): void {
    const pending = this.approvalGate.getPendingApprovals().find(p => p.id === approvalId);
    this.log("action_denied", { approvalId, toolName: pending?.toolName, args: pending?.args });
    this.approvalGate.deny(approvalId);
  }

  /**
   * Batch approve multiple actions
   */
  batchApprove(approvalIds: string[]): void {
    this.log("batch_approved", { approvalIds, count: approvalIds.length });
    this.approvalGate.batchApprove(approvalIds);
  }

  /**
   * Start the agent with an initial directive
   */
  async start(directive?: string): Promise<OperatorAgentResult> {
    if (this._status === "running" || this._status === "waiting") {
      throw new Error("Agent is already running");
    }

    this.log("agent_start", { directive, stage: this.currentStage });
    this.setStatus("running");
    this.abortController = new AbortController();

    // Mark setup stage as completed, move to recon
    if (this.currentStage === "setup") {
      this.stageManager.transitionTo("recon");
    }

    const session = this.config.session;
    const target = session.targets[0] || "";
    const stageDef = OPERATOR_STAGES[this.currentStage];

    // Initial user message
    const userMessage = directive || `Begin ${stageDef.name.toLowerCase()} phase for target: ${target}`;

    // Build initial system message (with attack knowledge based on directive)
    const systemMessage = this.buildSystemPrompt(target, stageDef, directive);

    // Always add the user's message so it appears in chat
    this.addMessage({
      role: "user",
      content: userMessage,
      createdAt: new Date(),
    });

    try {
      const result = await this.runAgentLoop(systemMessage, userMessage);
      this.log("agent_completed", { result });
      this.setStatus("idle"); // Back to idle, ready for new input
      return result;
    } catch (error: any) {
      if (this.abortController?.signal.aborted) {
        this.log("agent_stopped", { reason: "user_abort" });
        this.setStatus("idle"); // Back to idle after stop
        return { findingsCount: 0, pocPaths: [], summary: "Agent stopped by user" };
      }
      this.log("agent_error", { error: error?.message || String(error) });
      this.setStatus("failed");
      throw error;
    }
  }

  /**
   * Send a directive to the agent
   */
  async sendDirective(directive: string): Promise<void> {
    this.log("user_directive", { directive, currentStatus: this._status });

    // Auto-infer stage from directive intent
    const inference = inferStageFromDirective(directive);
    if (inference && inference.stage !== this.currentStage) {
      this.log("stage_inferred", {
        from: this.currentStage,
        to: inference.stage,
        confidence: inference.confidence,
        reason: inference.reason,
      });
      this.setStage(inference.stage);
    }

    if (this._status !== "running" && this._status !== "waiting") {
      // If idle or completed, start a new loop with this directive
      await this.start(directive);
      return;
    }

    this.userDirectives.push(directive);
    this.addMessage({
      role: "user",
      content: directive,
      createdAt: new Date(),
    });
  }

  /**
   * Stop the agent
   */
  stop(): void {
    this.log("agent_stop", { reason: "user_initiated" });
    if (this.abortController) {
      this.abortController.abort();
    }
    // Cleanup browser MCP client
    disconnectMcpClient().catch(() => {});
    // Deny all pending approvals
    this.approvalGate.denyAll();
    this.setStatus("idle"); // Ready for new input
  }

  /**
   * Get attack knowledge based on user directive
   */
  private getAttackKnowledge(directive?: string): string {
    if (!["test", "validate"].includes(this.currentStage)) return "";

    // Use existing inferVulnerabilityClasses to detect vuln types
    const vulnClasses = inferVulnerabilityClasses(directive || "");
    if (vulnClasses.length === 0) return "";

    // Map vuln classes to ATTACK_KNOWLEDGE keys
    const keyMap: Record<string, keyof typeof ATTACK_KNOWLEDGE> = {
      sqli: "sql_injection",
      xss: "xss_reflected",
      idor: "idor",
      command_injection: "command_injection",
      lfi: "path_traversal",
      ssti: "ssti",
      // Note: ssrf, crypto, jwt don't have direct matches - skip them
    };

    // Get attack knowledge for top 2 detected classes
    const sections = vulnClasses.slice(0, 2)
      .map(vc => {
        const key = keyMap[vc];
        if (!key || !ATTACK_KNOWLEDGE[key]) return null;
        const knowledge = ATTACK_KNOWLEDGE[key] as any;
        if (!knowledge.techniques || !knowledge.indicators) return null;
        return `### ${String(key).toUpperCase()}\n**Techniques:**\n${
          knowledge.techniques.map((t: any) => `- ${t.name}: ${t.how}`).join("\n")
        }\n**Vulnerable indicators:** ${knowledge.indicators.vulnerable.join(", ")}\n**Not vulnerable:** ${knowledge.indicators.notVulnerable.join(", ")}`;
      })
      .filter(Boolean);

    return sections.length > 0 ? `\n## Attack Knowledge\n${sections.join("\n\n")}` : "";
  }

  /**
   * Build resume context from attack surface and message history
   * Provides the agent with a summary of prior discoveries when resuming
   */
  private buildResumeContext(): string {
    if (!this.isResume) return "";

    const sections: string[] = [];

    // Attack surface summary - list known endpoints
    if (this.attackSurface && this.attackSurface.length > 0) {
      const endpoints = this.attackSurface.map(e => {
        const status = e.status && e.status !== "untested" ? ` [${e.status}]` : "";
        return `  - ${e.method} ${e.path}${status}`;
      }).join('\n');
      sections.push(`**Known Attack Surface (${this.attackSurface.length} endpoints):**\n${endpoints}`);
    }

    // Extract key findings from message history
    const findings: string[] = [];
    for (const msg of this.messages) {
      if (msg.role === "assistant" && typeof msg.content === "string") {
        const content = msg.content;
        // Look for structured findings patterns
        if (content.includes("Summary") || content.includes("discovered") ||
            content.includes("Endpoint") || content.includes("vulnerability") ||
            content.includes("Status") || content.includes("found")) {
          const lines = content.split('\n').filter(l => {
            const trimmed = l.trim();
            return (
              trimmed.startsWith('-') ||
              trimmed.startsWith('•') ||
              trimmed.includes('GET ') ||
              trimmed.includes('POST ') ||
              trimmed.includes('/api/') ||
              trimmed.includes('Status') ||
              trimmed.includes('401') ||
              trimmed.includes('200') ||
              trimmed.includes('404')
            );
          }).slice(0, 15);
          findings.push(...lines);
        }
      }
    }

    // Deduplicate findings
    const uniqueFindings = [...new Set(findings)].slice(0, 20);
    if (uniqueFindings.length > 0) {
      sections.push(`**Previous Discoveries:**\n${uniqueFindings.join('\n')}`);
    }

    if (sections.length === 0) {
      return "Session resumed - continuing from previous context.";
    }

    return `---
## SESSION RESUMED
This session has prior context. You have already performed reconnaissance.
Do NOT restart reconnaissance or call get_attack_surface/smart_enumerate again.
Proceed directly with the user's current request using the information below.

${sections.join('\n\n')}
---`;
  }

  /**
   * Build system prompt for current stage
   */
  private buildSystemPrompt(target: string, stageDef: typeof OPERATOR_STAGES[OperatorStage], directive?: string): string {
    const session = this.config.session;
    const isOffensiveStage = ["test", "validate"].includes(this.currentStage);

    // Build base prompt
    let prompt = `You are an expert penetration tester working alongside a human colleague.

## CRITICAL: Follow User Instructions
When your colleague gives you a specific instruction, STOP what you're doing and follow it immediately.
- User instructions override your current plan - always.
- Acknowledge what they asked: "Got it, focusing on X now..."
- Execute exactly what they requested before doing anything else.
- Only proceed autonomously if they haven't given specific guidance.

## CRITICAL: Execute POCs When Asked
When your colleague asks you to RUN, EXECUTE, or VALIDATE a POC/exploit:
- DO NOT just describe what the POC does - ACTUALLY RUN IT.
- Use execute_command or http_request to perform the actual attack.
- Show the real output so they can validate the vulnerability themselves.
- If you generated a POC earlier, execute it with real parameters against the target.
- The pentester needs to SEE the vulnerability work, not just read about it.

## How to Communicate
- Think out loud as you work. Share your reasoning naturally.
- When you find something interesting, explain why it caught your attention.

## IMPORTANT: Pause & Ask Pattern
After completing significant actions (discovery, tests, findings), PAUSE and offer numbered choices:

"I've completed [action]. Based on what I found, here are some options:

[1] [First suggestion with brief rationale]
[2] [Second suggestion]
[3] [Third suggestion]

Which would you like me to pursue? Or type your own direction."

The user can press 1, 2, or 3 to quickly select an option.
If no response after ~10 seconds, proceed with the most promising approach.

## Current Assessment
Target: ${target}
Stage: ${stageDef.name} - ${stageDef.description}
${session.config?.authenticationInstructions ? `\nSession context: ${session.config.authenticationInstructions}` : ""}

## What We Know So Far
${this.isResume ? this.buildResumeContext() : (this.findingsSummary || "Just starting - no findings yet.")}

## Testing Guidance
${session.config?.outcomeGuidance || Session.DEFAULT_OUTCOME_GUIDANCE}

## Browser Tools (Validation & Evidence)
You have browser automation for when you need real browser execution:

**Tools:** browser_navigate, browser_fill, browser_click, browser_evaluate, browser_console, browser_screenshot

**When to use browsers (vs http_request):**
- VALIDATING XSS: After http_request shows unencoded reflection, use browser to prove JS executes
- DOM-based XSS: These ONLY work in browsers (client-side JS vulnerabilities)
- Evidence capture: Screenshots for POC documentation
- Complex interactions: Multi-step flows requiring JS rendering

**Optimal XSS testing flow:**
1. http_request with payloads - look for unencoded reflection in response
2. If reflection found → browser_navigate + browser_console to confirm execution
3. browser_screenshot for evidence → document_finding

Use http_request for speed/discovery. Use browser to PROVE vulnerabilities work.

## Your Approach
Be methodical but follow interesting leads. Quality over quantity.
A good pentest isn't about running every tool - it's about understanding
the application and finding the paths an attacker would actually exploit.

When you discover something notable:
1. Explain what you found and why it matters
2. Use the [1]/[2]/[3] format to offer next steps
3. Wait for user selection, or continue after ~10 seconds

Example suggestions by stage:
- Recon: "[1] Map the attack surface" "[2] Check authentication flows" "[3] Look for API endpoints"
- Test: "[1] Test for SQL injection on /login" "[2] Check for IDOR on /api/users" "[3] Try XSS on search"
- Validate: "[1] Create POC for the SQLi finding" "[2] Test other endpoints" "[3] Document and move on"

Document significant findings using the document_finding tool.`;

    // On resume, context is provided in two ways:
    // 1. buildResumeContext() adds attack surface and findings to the system prompt
    // 2. runAgentLoop() includes recent messages in the conversation history
    // This ensures the agent knows about prior discoveries and won't restart recon

    // Inject cognitive loop for offensive stages (test/validate)
    if (isOffensiveStage) {
      prompt += OFFENSIVE_COGNITIVE_LOOP;
    }

    // Inject attack knowledge based on directive
    const attackKnowledge = this.getAttackKnowledge(directive);
    if (attackKnowledge) {
      prompt += attackKnowledge;
    }

    return prompt;
  }

  /**
   * Run the main agent loop
   */
  private async runAgentLoop(systemMessage: string, initialUserMessage: string): Promise<OperatorAgentResult> {

    const session = this.config.session;
    const messages: Array<{ role: "system" | "user" | "assistant"; content: string }> = [
      { role: "system", content: systemMessage },
    ];

    // On resume, include recent conversation history for context
    // This gives the AI model awareness of previous interactions
    if (this.isResume && this.messages.length > 0) {
      const recentMessages = this.messages.slice(-20); // Last 20 messages for context
      for (const msg of recentMessages) {
        if (msg.role === "user" || msg.role === "assistant") {
          messages.push({ role: msg.role, content: String(msg.content) });
        }
      }
    }

    // Add current user directive
    messages.push({ role: "user", content: initialUserMessage });

    // Create tools with approval gate wrapper
    // Pass operatorMode: true to enable streaming stdout logs
    const baseTools = createPentestTools(
      session,
      this.config.model,
      undefined, // toolOverride
      undefined, // onTokenUsage
      this.abortController?.signal,
      true // operatorMode - enables streaming stdout
    );

    // Add browser tools for operator mode (HITL) only
    const evidenceDir = join(session.rootPath, "evidence");
    const browserTools = createBrowserTools(
      session.targets[0] || "",
      evidenceDir,
      "operator", // Operator mode for user-driven reconnaissance
      undefined,  // logger - could be passed in future
      this.abortController?.signal
    );

    // Add POC tools for offensive stages (test/validate)
    let pocTools: Record<string, any> = {};
    if (["test", "validate"].includes(this.currentStage)) {
      const logger = new Logger(session, 'operator-agent.log');
      const { create_poc } = createPocTool(
        {
          id: session.id,
          rootPath: session.rootPath,
          pocsPath: join(session.rootPath, "pocs"),
          findingsPath: join(session.rootPath, "findings"),
          logsPath: join(session.rootPath, "logs"),
        },
        logger
      );
      pocTools = { create_poc };
    }

    // Add authentication subagent tool - define schema first for type inference
    const RunAuthSubagentInput = z.object({
      target: z.string().describe("Target URL to authenticate against"),
      username: z.string().optional().describe("Username if available"),
      password: z.string().optional().describe("Password if available"),
      reason: z.string().describe("Why you need to run authentication"),
      toolCallDescription: z.string().describe("A concise description of what this tool call is doing"),
    });

    const run_auth_subagent = tool({
      description: `Run the authentication subagent to obtain an authenticated session.

Call this when:
- You need to access authenticated endpoints
- Current session is expired or invalid
- User requested authentication
- Complex auth flow detected (OAuth, SAML, CSRF tokens, SPA logins)

Credentials are optional - if not provided, will discover auth requirements
and probe for self-registration if available.

This tool requires user approval (T3 tier - Probing).`,
      inputSchema: RunAuthSubagentInput,
      execute: async ({ target, username, password, reason }: z.infer<typeof RunAuthSubagentInput>) => {
        // Emit event for UI to show auth in progress
        this.emit("operator-event", { type: "auth-subagent-started", target });
        this.log("auth_subagent_started", { target, reason, hasCredentials: !!(username || password) });

        try {
          const result = await runAuthenticationSubagent({
            input: {
              target,
              session,
              credentials: username || password ? { username, password } : undefined,
            },
            model: this.config.model,
            enableBrowserTools: true,
          });

          // Emit result
          this.emit("operator-event", {
            type: "auth-subagent-completed",
            success: result.success,
            cookies: result.exportedCookies,
            headers: result.exportedHeaders,
          });

          this.log("auth_subagent_completed", {
            success: result.success,
            strategy: result.strategy,
            summary: result.summary,
          });

          return {
            success: result.success,
            authenticated: result.success,
            strategy: result.strategy,
            sessionCookie: result.exportedCookies || "",
            headers: result.exportedHeaders || {},
            authBarrier: result.authBarrier,
            summary: result.summary,
            message: result.success
              ? `Authentication successful. Strategy: ${result.strategy}. ${result.summary}`
              : `Authentication failed. ${result.summary}${result.authBarrier ? ` Barrier: ${result.authBarrier.type}` : ""}`,
          };
        } catch (error: any) {
          this.emit("operator-event", {
            type: "auth-subagent-completed",
            success: false,
          });
          this.log("auth_subagent_error", { error: error.message });
          return {
            success: false,
            authenticated: false,
            message: `Auth subagent error: ${error.message}`,
          };
        }
      },
    });

    const authTools = { run_auth_subagent };

    // Merge all tools and wrap with approval checking
    const allTools = { ...baseTools, ...browserTools, ...pocTools, ...authTools };

    // Filter tools based on toolset state
    const activeToolNames = getActiveToolNames(session.config?.toolsetState);
    const filteredTools: Record<string, any> = {};
    for (const [toolName, tool] of Object.entries(allTools)) {
      if (activeToolNames.includes(toolName)) {
        filteredTools[toolName] = tool;
      }
    }

    // Wrap filtered tools with approval checking
    const wrappedTools = this.wrapToolsWithApproval(filteredTools);

    let findingsCount = 0;
    let pocPaths: string[] = [];
    let continueLoop = true;
    let iterations = 0;
    const maxIterations = 50;

    while (continueLoop && iterations < maxIterations) {
      iterations++;

      // Check for user directives
      if (this.userDirectives.length > 0) {
        const directive = this.userDirectives.shift()!;
        messages.push({ role: "user", content: directive });
      }

      try {
        // Log the full model input for trajectory collection
        this.log("model_turn_start", {
          iteration: iterations,
          system: systemMessage,
          messages: messages.slice(1), // Full conversation context
          model: this.config.model,
        });

        const streamResult = streamResponse({
          prompt: initialUserMessage,
          model: this.config.model,
          system: systemMessage,
          messages: messages.slice(1) as any, // exclude system message (passed separately)
          tools: wrappedTools,
          stopWhen: stepCountIs(100), // Allow multi-step tool execution within each iteration
          abortSignal: this.abortController?.signal,
          onStepFinish: (step) => {
            console.log(step.usage)
            console.log(this.config.onTokenUsage)
            if (step.usage && this.config.onTokenUsage) {
              console.log(step.usage)
              this.config.onTokenUsage(
                step.usage.inputTokens ?? 0,
                step.usage.outputTokens ?? 0
              );
            }
          }
        });

        // Process stream events in order
        // ensures text appears before tool calls in the UI
        let assistantContent = "";
        let currentAssistantMsgIndex = -1;

        for await (const chunk of streamResult.fullStream) {
          // Check for user directives - interrupt to process them
          if (this.userDirectives.length > 0 && this.abortController && !this.abortController.signal.aborted) {
            this.abortController.abort();
          }

          switch (chunk.type) {
            case "text-delta":
              // Accumulate text and update/create assistant message
              assistantContent += chunk.text;
              if (currentAssistantMsgIndex === -1) {
                // Create new assistant message
                this.addMessage({
                  role: "assistant",
                  content: chunk.text,
                  createdAt: new Date(),
                });
                currentAssistantMsgIndex = this.messages.length - 1;
              } else {
                // Update existing assistant message
                const existingMsg = this.messages[currentAssistantMsgIndex];
                this.updateMessage(currentAssistantMsgIndex, {
                  ...existingMsg,
                  content: (existingMsg.content || "") + chunk.text,
                });
              }
              break;

            case "tool-call":
              // Add pending tool message (comes after text in stream order)
              const args = (chunk as any).input || (chunk as any).args || {};
              const description = args.toolCallDescription || chunk.toolName;

              this.log("tool_call", {
                toolCallId: chunk.toolCallId,
                toolName: chunk.toolName,
                args,
              });

              this.addMessage({
                role: "tool",
                status: "pending",
                toolCallId: chunk.toolCallId,
                toolName: chunk.toolName,
                content: description,
                args,
                createdAt: new Date(),
              });
              // Reset so next text creates a new assistant message
              currentAssistantMsgIndex = -1;
              break;

            case "tool-result":
              // Update tool message to completed
              // Note: AI SDK uses 'output' not 'result' for tool-result chunks
              const msgIdx = this.toolCallIdToIndex.get(chunk.toolCallId) ?? -1;
              if (msgIdx !== -1) {
                const existingMsg = this.messages[msgIdx];
                const toolOutput = (chunk as any).output;

                this.log("tool_result", {
                  toolCallId: chunk.toolCallId,
                  toolName: existingMsg.toolName,
                  result: toolOutput,
                });

                this.updateMessage(msgIdx, {
                  ...existingMsg,
                  status: "completed",
                  content: `+ ${existingMsg.content}`,
                  result: toolOutput,
                });

                // Extract findings and emit sidebar events
                this.extractFindings(existingMsg.toolName || "", toolOutput);
                this.emitSidebarEvents(toolOutput);
              }
              break;
          }
        }

        // Get final result
        const finalResult = await streamResult;
        const toolCalls = await finalResult.toolCalls;
        const usage = await finalResult.usage;

        // Log complete model output for trajectory collection
        this.log("model_turn_end", {
          iteration: iterations,
          assistantContent,
          toolCalls: toolCalls?.map((tc: any) => ({
            toolName: tc.toolName,
            toolCallId: tc.toolCallId,
            args: tc.input || tc.args,
          })),
          usage, // token counts
        });

        // Add assistant message to history
        if (assistantContent) {
          messages.push({ role: "assistant", content: assistantContent });
        }

        // Check if we should continue
        // Stop if: no tool calls AND no pending user directives
        const hasToolCalls = toolCalls && toolCalls.length > 0;
        const hasPendingDirectives = this.userDirectives.length > 0;

        if (!hasToolCalls && !hasPendingDirectives) {
          continueLoop = false;
        }

        // Check for complete_testing tool call (but still process pending directives)
        if (toolCalls?.some((tc: any) => tc.toolName === "complete_testing") && !hasPendingDirectives) {
          continueLoop = false;
        }

      } catch (error: any) {
        if (error instanceof ApprovalBlockedError) {
          // Action was blocked in plan mode - add message and continue
          this.log("action_blocked", { error: error.message });
          this.addMessage({
            role: "system",
            content: `Action blocked: ${error.message}`,
            createdAt: new Date(),
          });
          continue;
        }
        if (error instanceof ApprovalDeniedError) {
          // User denied action - add message and continue
          this.log("action_denied_error", { error: error.message });
          this.addMessage({
            role: "system",
            content: `Action denied by user`,
            createdAt: new Date(),
          });
          continue;
        }
        // Check if aborted due to user directive - continue to process it
        if (this.abortController?.signal.aborted && this.userDirectives.length > 0) {
          // Reset abort controller for next iteration
          this.abortController = new AbortController();
          continue;
        }
        // Check if just a user-initiated stop (no pending directives)
        if (this.abortController?.signal.aborted) {
          break; // Exit loop cleanly
        }
        throw error;
      }
    }

    const result = {
      findingsCount,
      pocPaths,
      summary: `Completed ${iterations} iterations in ${this.currentStage} stage`,
    };
    this.log("agent_loop_completed", { iterations, stage: this.currentStage, result });
    return result;
  }

  /**
   * Wrap all tools with approval gate checking and progress logging
   */
  /**
   * Tools that support streaming stdout (don't show progress animation)
   */
  private static STREAMING_TOOLS = new Set(["execute_command"]);

  /**
   * Cute ASCII animation frames for non-streaming tools
   * Bouncing dot in a track
   */
  private static PROGRESS_FRAMES = [
    "∙ ● ∙ ∙ ∙",
    "∙ ∙ ● ∙ ∙",
    "∙ ∙ ∙ ● ∙",
    "∙ ∙ ∙ ∙ ●",
    "∙ ∙ ∙ ● ∙",
    "∙ ∙ ● ∙ ∙",
    "∙ ● ∙ ∙ ∙",
    "● ∙ ∙ ∙ ∙",
  ];

  private wrapToolsWithApproval(tools: Record<string, any>): Record<string, any> {
    const wrapped: Record<string, any> = {};

    for (const [name, tool] of Object.entries(tools)) {
      wrapped[name] = {
        ...tool,
        execute: async (args: any, context: any) => {
          const toolCallId = context?.toolCallId || `tc-${Date.now()}`;

          try {
            // Check approval
            await this.approvalGate.check(name, toolCallId, args);

            // Emit starting log
            this.addToolLog(toolCallId, this.getToolStartLog(name, args));

            // Inject emitLog callback into extended context for streaming tools
            const extendedContext = {
              ...context,
              toolCallId,
              emitLog: (line: string) => this.addToolLog(toolCallId, line),
            };

            // Check if this tool should run in background by default
            if (isBackgroundTool(name)) {
              const task = taskManager.createTask(name);
              this.addToolLog(toolCallId, `→ running in background (task: ${task.id})`);

              // Fire and forget - do NOT await
              (async () => {
                taskManager.updateStatus(task.id, "running");
                try {
                  const result = await tool.execute(args, extendedContext);
                  taskManager.setResult(task.id, result);
                } catch (err: any) {
                  taskManager.setError(task.id, err.message);
                }
              })();

              // Return immediately with task ID
              return {
                success: true,
                background: true,
                taskId: task.id,
                message: `${name} started in background. Use check_task_status("${task.id}") to get results.`,
              };
            }

            // Only show progress animation for tools that don't support streaming
            const supportsStreaming = OperatorAgent.STREAMING_TOOLS.has(name);
            let progressInterval: NodeJS.Timeout | null = null;

            if (!supportsStreaming) {
              let frameIndex = 0;
              progressInterval = setInterval(() => {
                const frame = OperatorAgent.PROGRESS_FRAMES[frameIndex];
                this.addToolLog(toolCallId, frame);
                frameIndex = (frameIndex + 1) % OperatorAgent.PROGRESS_FRAMES.length;
              }, 200);
            }

            try {
              // Execute original tool with extended context
              const result = await tool.execute(args, extendedContext);

              // Clear progress interval if set
              if (progressInterval) {
                clearInterval(progressInterval);
              }

              // Emit result summary log (skip for streaming tools - they log their own output)
              if (!supportsStreaming) {
                const resultLog = this.getToolResultLog(name, result);
                if (resultLog) {
                  this.addToolLog(toolCallId, resultLog);
                }
              }

              return result;
            } finally {
              if (progressInterval) {
                clearInterval(progressInterval);
              }
            }
          } catch (error) {
            if (error instanceof ApprovalBlockedError || error instanceof ApprovalDeniedError) {
              // Return a message indicating the action was blocked/denied
              return {
                success: false,
                error: error.message,
                blocked: true,
              };
            }
            throw error;
          }
        },
      };
    }

    return wrapped;
  }

  /**
   * Get a starting log message for a tool
   */
  private getToolStartLog(toolName: string, args: any): string {
    switch (toolName) {
      case "execute_command":
        const cmd = String(args.command || "").slice(0, 50);
        return `$ ${cmd}${args.command?.length > 50 ? "..." : ""}`;
      case "http_request":
        const method = (args.method || "GET").toUpperCase();
        const url = String(args.url || "").slice(0, 40);
        return `${method} ${url}${args.url?.length > 40 ? "..." : ""}`;
      case "browser_navigate":
        return `navigating to ${String(args.url || "").slice(0, 40)}`;
      case "Grep":
      case "grep":
        return `searching for "${String(args.pattern || "").slice(0, 30)}"`;
      case "Read":
      case "read_file":
        return `reading ${String(args.file_path || args.path || "").slice(0, 40)}`;
      default:
        return `executing ${toolName}`;
    }
  }

  /**
   * Get a result summary log for a tool
   */
  private getToolResultLog(toolName: string, result: any): string | null {
    if (!result) return null;

    // Error results
    if (result.success === false && result.error) {
      return `✗ ${String(result.error).slice(0, 80)}`;
    }

    // HTTP request results
    if (result.status !== undefined && result.statusText !== undefined) {
      const bodyPreview = result.body
        ? ` - ${String(result.body).slice(0, 50)}${result.body.length > 50 ? "..." : ""}`
        : "";
      return `→ ${result.status} ${result.statusText}${bodyPreview}`;
    }

    // Command results with stdout
    if (result.stdout !== undefined) {
      const stdout = String(result.stdout).trim();
      if (stdout && stdout !== "(no output)") {
        const lines = stdout.split("\n").filter(Boolean);
        if (lines.length > 0) {
          const firstLine = lines[0].slice(0, 70);
          if (lines.length > 1) {
            return `→ ${firstLine}${firstLine.length < lines[0].length ? "..." : ""} (+${lines.length - 1} more lines)`;
          }
          return `→ ${firstLine}`;
        }
      }
      // Command succeeded but no meaningful output
      if (result.success) {
        return "→ done (no output)";
      }
    }

    // Background task started
    if (result.background && result.taskId) {
      return `→ background task: ${result.taskId}`;
    }

    // Array results (endpoints, urls, etc)
    if (Array.isArray(result)) {
      if (result.length === 0) return "→ found 0 items";
      const preview = typeof result[0] === "string"
        ? result[0].slice(0, 40)
        : JSON.stringify(result[0]).slice(0, 40);
      return `→ found ${result.length} items (${preview}${result.length > 1 ? ", ..." : ""})`;
    }

    // Object with endpoints array
    if (result.endpoints?.length !== undefined) {
      return `→ found ${result.endpoints.length} endpoints`;
    }

    // Object with urls array
    if (result.urls?.length !== undefined) {
      return `→ found ${result.urls.length} URLs`;
    }

    // Object with findings
    if (result.findings?.length !== undefined) {
      return `→ found ${result.findings.length} findings`;
    }

    // Generic success with message
    if (result.success && result.message) {
      return `→ ${String(result.message).slice(0, 80)}`;
    }

    // Generic success
    if (result.success === true) {
      return "→ done";
    }

    // Fallback: try to summarize the object
    if (typeof result === "object") {
      const keys = Object.keys(result);
      const importantKeys = keys.filter(k =>
        !["success", "error", "command", "toolCallDescription"].includes(k)
      );
      if (importantKeys.length > 0) {
        const previews = importantKeys.slice(0, 2).map(k => {
          const val = result[k];
          if (Array.isArray(val)) return `${k}: ${val.length} items`;
          if (typeof val === "string") return `${k}: ${val.slice(0, 20)}${val.length > 20 ? "..." : ""}`;
          if (typeof val === "number") return `${k}: ${val}`;
          return null;
        }).filter(Boolean);
        if (previews.length > 0) {
          return `→ ${previews.join(", ")}`;
        }
      }
    }

    return null;
  }

  /**
   * Emit sidebar events for tool results that update UI state
   */
  private emitSidebarEvents(output: any): void {
    if (!output || typeof output !== "object") return;

    // Attack surface updates
    if (output.endpoints && Array.isArray(output.endpoints)) {
      this.emit("operator-event", {
        type: "attack-surface-updated",
        endpoints: output.endpoints,
      });
    }
    // Credential discoveries
    if (output.credential) {
      this.emit("operator-event", {
        type: "credential-found",
        credential: output.credential,
      });
    }
    // Verified findings
    if (output.finding) {
      this.emit("operator-event", {
        type: "finding-verified",
        finding: output.finding,
      });
    }
    // Endpoint status changes
    if (output.endpointId && output.status) {
      this.emit("operator-event", {
        type: "endpoint-status-changed",
        endpointId: output.endpointId,
        status: output.status,
        vulnType: output.vulnType,
      });
    }
  }

  /**
   * Extract key findings from tool results and update the summary
   */
  private extractFindings(toolName: string, result: any): void {
    if (!result) return;

    const resultStr = typeof result === "string" ? result : JSON.stringify(result);
    const findings: string[] = [];

    // HTTP response analysis
    if (toolName === "http_request") {
      const status = result?.status || result?.statusCode;
      const url = result?.url || "";

      // Interesting status codes
      if (status === 403) {
        findings.push(`- 403 Forbidden at ${url} (potential access control to bypass)`);
      } else if (status === 401) {
        findings.push(`- 401 Unauthorized at ${url} (auth required)`);
      } else if (status === 500) {
        findings.push(`- 500 Error at ${url} (potential for error-based info leak)`);
      }

      // Check for sensitive data patterns in response
      if (resultStr.includes("password") || resultStr.includes("token") || resultStr.includes("api_key")) {
        findings.push(`- Sensitive keywords found in response from ${url}`);
      }
    }

    // Crawl results
    if (toolName === "crawl" && result?.urls) {
      const urlCount = Array.isArray(result.urls) ? result.urls.length : 0;
      if (urlCount > 0) {
        findings.push(`- Discovered ${urlCount} URLs from crawling`);
      }
    }

    // Document finding tool (explicit finding)
    if (toolName === "document_finding") {
      const title = result?.title || result?.name || "Finding";
      findings.push(`- FINDING: ${title}`);
    }

    // Update summary if we found something notable
    if (findings.length > 0) {
      const timestamp = new Date().toLocaleTimeString();
      const newFindings = findings.map((f) => `[${timestamp}] ${f}`).join("\n");

      this.log("findings_extracted", { toolName, findings });

      if (this.findingsSummary) {
        this.findingsSummary += "\n" + newFindings;
      } else {
        this.findingsSummary = newFindings;
      }

      // Keep summary bounded (last ~20 findings)
      const lines = this.findingsSummary.split("\n");
      if (lines.length > 20) {
        this.findingsSummary = lines.slice(-20).join("\n");
      }
    }
  }
}

/**
 * Create a new Operator agent
 */
export function createOperatorAgent(config: OperatorAgentConfig): OperatorAgent {
  return new OperatorAgent(config);
}

export type { OperatorMode, OperatorStage, PermissionTier, PendingApproval, ActionHistoryEntry };
