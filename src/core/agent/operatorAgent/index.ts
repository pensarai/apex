/**
 * OperatorAgent - Operator Mode Agent
 *
 * A single agent that collaborates with the pentester through approval gates.
 * Unlike SwarmMode, this runs one agent that waits for approval on risky actions.
 */

import { EventEmitter } from "events";
import { stepCountIs } from "ai";
import type { AIModel } from "../../ai";
import { streamResponse } from "../../ai/ai";
import { Session } from "../../session";
import {
  ApprovalGate,
  ApprovalBlockedError,
  ApprovalDeniedError,
  StageManager,
  type OperatorMode,
  type OperatorStage,
  type PermissionTier,
  type PendingApproval,
  type ActionHistoryEntry,
  type OperatorEvent,
  OPERATOR_STAGES,
} from "../../operator";
import { createPentestTools } from "../tools";
import type { DisplayMessage } from "../../../tui/components/agent-display";

export type OperatorAgentStatus = "idle" | "running" | "waiting" | "paused" | "completed" | "failed";

export interface OperatorAgentConfig {
  session: Session.SessionInfo;
  model: AIModel;
  initialMode?: OperatorMode;
  autoApproveTier?: PermissionTier;
  initialStage?: OperatorStage;
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
  private messages: DisplayMessage[] = [];
  private userDirectives: string[] = [];
  private findingsSummary: string = "";

  // Operator components
  readonly approvalGate: ApprovalGate;
  readonly stageManager: StageManager;

  constructor(config: OperatorAgentConfig) {
    super();
    this.config = config;

    // Initialize approval gate
    this.approvalGate = new ApprovalGate({
      mode: config.initialMode || "manual",
      autoApproveTier: config.autoApproveTier || 2,
    });

    // Initialize stage manager
    this.stageManager = new StageManager(config.initialStage || "setup");

    // Forward approval gate events
    this.approvalGate.on("operator-event", (event: OperatorEvent) => {
      this.emit("operator-event", event);
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
    });
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

  private setStatus(status: OperatorAgentStatus): void {
    this._status = status;
    this.emit("status-change", status);
  }

  private addMessage(message: DisplayMessage): void {
    this.messages.push(message);
    this.emit("message", message);
  }

  private updateMessage(index: number, message: DisplayMessage): void {
    this.messages[index] = message;
    this.emit("message-updated", { index, message });
  }

  /**
   * Change the operating mode
   */
  setMode(mode: OperatorMode): void {
    this.approvalGate.updateConfig({ mode });
    this.emit("operator-event", { type: "mode-changed", mode });
  }

  /**
   * Change the auto-approve tier
   */
  setAutoApproveTier(tier: PermissionTier): void {
    this.approvalGate.updateConfig({ autoApproveTier: tier });
  }

  /**
   * Transition to a new stage
   */
  setStage(stage: OperatorStage): void {
    this.stageManager.transitionTo(stage);
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
    this.approvalGate.approve(approvalId);
  }

  /**
   * Deny a pending action
   */
  deny(approvalId: string): void {
    this.approvalGate.deny(approvalId);
  }

  /**
   * Batch approve multiple actions
   */
  batchApprove(approvalIds: string[]): void {
    this.approvalGate.batchApprove(approvalIds);
  }

  /**
   * Start the agent with an initial directive
   */
  async start(directive?: string): Promise<OperatorAgentResult> {
    if (this._status === "running" || this._status === "waiting") {
      throw new Error("Agent is already running");
    }

    this.setStatus("running");
    this.abortController = new AbortController();

    // Mark setup stage as completed, move to recon
    if (this.currentStage === "setup") {
      this.stageManager.transitionTo("recon");
    }

    const session = this.config.session;
    const target = session.targets[0] || "";
    const stageDef = OPERATOR_STAGES[this.currentStage];

    // Build initial system message
    const systemMessage = this.buildSystemPrompt(target, stageDef);

    // Initial user message
    const userMessage = directive || `Begin ${stageDef.name.toLowerCase()} phase for target: ${target}`;

    this.addMessage({
      role: "user",
      content: userMessage,
      createdAt: new Date(),
    });

    try {
      const result = await this.runAgentLoop(systemMessage, userMessage);
      this.setStatus("idle"); // Back to idle, ready for new input
      return result;
    } catch (error) {
      if (this.abortController?.signal.aborted) {
        this.setStatus("idle"); // Back to idle after stop
        return { findingsCount: 0, pocPaths: [], summary: "Agent stopped by user" };
      }
      this.setStatus("failed");
      throw error;
    }
  }

  /**
   * Send a directive to the agent
   */
  async sendDirective(directive: string): Promise<void> {
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
    if (this.abortController) {
      this.abortController.abort();
    }
    // Deny all pending approvals
    this.approvalGate.denyAll();
    this.setStatus("idle"); // Ready for new input
  }

  /**
   * Build system prompt for current stage
   */
  private buildSystemPrompt(target: string, stageDef: typeof OPERATOR_STAGES[OperatorStage]): string {
    const session = this.config.session;

    return `You are an expert penetration tester working alongside a human colleague.

## How to Communicate
- Think out loud as you work. Share your reasoning naturally.
- When you find something interesting, explain why it caught your attention.
- After discoveries, suggest 2-3 concrete next steps with brief explanations.
- If your colleague doesn't respond, proceed with the most promising approach.
- Periodically synthesize: "Here's what we've learned so far..."

## Current Assessment
Target: ${target}
Stage: ${stageDef.name} - ${stageDef.description}
${session.config?.authenticationInstructions ? `\nSession context: ${session.config.authenticationInstructions}` : ""}

## What We Know So Far
${this.findingsSummary || "Just starting - no findings yet."}

## Testing Guidance
${session.config?.outcomeGuidance || Session.DEFAULT_OUTCOME_GUIDANCE}

## Your Approach
Be methodical but follow interesting leads. Quality over quantity.
A good pentest isn't about running every tool - it's about understanding
the application and finding the paths an attacker would actually exploit.

When you discover something notable:
1. Explain what you found and why it matters
2. Offer 2-3 directions we could explore next
3. If I don't respond, pick the most promising path and continue

Document significant findings using the document_finding tool.`;
  }

  /**
   * Run the main agent loop
   */
  private async runAgentLoop(systemMessage: string, initialUserMessage: string): Promise<OperatorAgentResult> {
    const session = this.config.session;
    const messages: Array<{ role: "system" | "user" | "assistant"; content: string }> = [
      { role: "system", content: systemMessage },
      { role: "user", content: initialUserMessage },
    ];

    // Create tools with approval gate wrapper
    const baseTools = createPentestTools(session, this.config.model);

    // Wrap tools with approval checking
    const wrappedTools = this.wrapToolsWithApproval(baseTools);

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
        const streamResult = streamResponse({
          prompt: initialUserMessage,
          model: this.config.model,
          system: systemMessage,
          messages: messages.slice(1) as any, // exclude system message (passed separately)
          tools: wrappedTools,
          stopWhen: stepCountIs(100), // Allow multi-step tool execution within each iteration
          abortSignal: this.abortController?.signal,
          onStepFinish: (step) => this.handleStepFinish(step),
        });

        // Consume stream
        let assistantContent = "";
        for await (const chunk of streamResult.fullStream) {
          if (chunk.type === "text-delta") {
            assistantContent += chunk.text;
          }
        }

        // Get final result
        const finalResult = await streamResult;
        const toolCalls = await finalResult.toolCalls;

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
          this.addMessage({
            role: "system",
            content: `Action blocked: ${error.message}`,
            createdAt: new Date(),
          });
          continue;
        }
        if (error instanceof ApprovalDeniedError) {
          // User denied action - add message and continue
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

    return {
      findingsCount,
      pocPaths,
      summary: `Completed ${iterations} iterations in ${this.currentStage} stage`,
    };
  }

  /**
   * Wrap all tools with approval gate checking
   */
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

            // Execute original tool
            return await tool.execute(args, context);
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
   * Handle step finish callback from AI streaming
   */
  private handleStepFinish(step: any): void {
    const { text, toolCalls, toolResults } = step;

    // Check for user directives - if user typed something, interrupt to process it sooner
    if (this.userDirectives.length > 0 && this.abortController && !this.abortController.signal.aborted) {
      // Abort current stream to pick up user input on next iteration
      this.abortController.abort();
      // Note: The abort will be caught in runAgentLoop, which will continue and pick up the directive
    }

    // Handle text content
    if (text && text.trim()) {
      const lastMsg = this.messages[this.messages.length - 1];
      if (lastMsg && lastMsg.role === "assistant") {
        this.updateMessage(this.messages.length - 1, {
          ...lastMsg,
          content: (lastMsg.content || "") + text,
        });
      } else {
        this.addMessage({
          role: "assistant",
          content: text,
          createdAt: new Date(),
        });
      }
    }

    // Handle tool calls
    if (toolCalls && toolCalls.length > 0) {
      for (const tc of toolCalls) {
        const args = (tc as any).input || {};
        const description = args.toolCallDescription || tc.toolName;

        this.addMessage({
          role: "tool",
          status: "pending",
          toolCallId: tc.toolCallId,
          toolName: tc.toolName,
          content: description,
          args,
          createdAt: new Date(),
        });
      }
    }

    // Handle tool results
    if (toolResults && toolResults.length > 0) {
      for (const tr of toolResults) {
        const msgIdx = this.messages.findIndex(
          (m) => m.role === "tool" && (m as any).toolCallId === tr.toolCallId
        );
        if (msgIdx !== -1) {
          const existingMsg = this.messages[msgIdx];
          this.updateMessage(msgIdx, {
            ...existingMsg,
            status: "completed",
            content: `+ ${existingMsg.content}`,
            result: (tr as any).output,
          });

          // Extract findings from significant tool results
          this.extractFindings(existingMsg.toolName || "", (tr as any).output);
        }
      }
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
