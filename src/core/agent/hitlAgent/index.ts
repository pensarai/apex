/**
 * HITLAgent - Human-in-the-Loop Agent
 *
 * A single agent that collaborates with the pentester through approval gates.
 * Unlike SwarmMode, this runs one agent that waits for approval on risky actions.
 */

import { EventEmitter } from "events";
import type { AIModel } from "../../ai";
import { streamResponse } from "../../ai/ai";
import { Session } from "../../session";
import {
  ApprovalGate,
  ApprovalBlockedError,
  ApprovalDeniedError,
  StageManager,
  type HITLMode,
  type HITLStage,
  type PermissionTier,
  type PendingApproval,
  type ActionHistoryEntry,
  type HITLEvent,
  HITL_STAGES,
} from "../../hitl";
import { createPentestTools } from "../tools";
import type { DisplayMessage } from "../../../tui/components/agent-display";

export type HITLAgentStatus = "idle" | "running" | "waiting" | "paused" | "completed" | "failed";

export interface HITLAgentConfig {
  session: Session.SessionInfo;
  model: AIModel;
  initialMode?: HITLMode;
  autoApproveTier?: PermissionTier;
  initialStage?: HITLStage;
}

export interface HITLAgentResult {
  findingsCount: number;
  pocPaths: string[];
  summary: string;
  error?: string;
}

/**
 * HITLAgent class - single agent with approval gates
 */
export class HITLAgent extends EventEmitter {
  private _status: HITLAgentStatus = "idle";
  private config: HITLAgentConfig;
  private abortController: AbortController | null = null;
  private messages: DisplayMessage[] = [];
  private userDirectives: string[] = [];

  // HITL components
  readonly approvalGate: ApprovalGate;
  readonly stageManager: StageManager;

  constructor(config: HITLAgentConfig) {
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
    this.approvalGate.on("hitl-event", (event: HITLEvent) => {
      this.emit("hitl-event", event);
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
    this.stageManager.on("hitl-event", (event: HITLEvent) => {
      this.emit("hitl-event", event);
    });
  }

  get status(): HITLAgentStatus {
    return this._status;
  }

  get mode(): HITLMode {
    return this.approvalGate.getConfig().mode;
  }

  get currentStage(): HITLStage {
    return this.stageManager.getCurrentStage();
  }

  get allMessages(): DisplayMessage[] {
    return [...this.messages];
  }

  private setStatus(status: HITLAgentStatus): void {
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
  setMode(mode: HITLMode): void {
    this.approvalGate.updateConfig({ mode });
    this.emit("hitl-event", { type: "mode-changed", mode });
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
  setStage(stage: HITLStage): void {
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
  async start(directive?: string): Promise<HITLAgentResult> {
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
    const stageDef = HITL_STAGES[this.currentStage];

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
      this.setStatus("completed");
      return result;
    } catch (error) {
      if (this.abortController?.signal.aborted) {
        this.setStatus("completed");
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
    this.setStatus("completed");
  }

  /**
   * Build system prompt for current stage
   */
  private buildSystemPrompt(target: string, stageDef: typeof HITL_STAGES[HITLStage]): string {
    const session = this.config.session;

    return `You are an AI security researcher conducting a penetration test.

## Target
${target}

## Current Stage: ${stageDef.name}
${stageDef.description}

## Suggested Actions for This Stage
${stageDef.suggestedActions.map((a) => `- ${a}`).join("\n")}

## Guidelines
- Work methodically through the current stage
- Explain your reasoning before taking actions
- When you find something interesting, investigate it thoroughly
- Document any findings using the document_finding tool
- Move to the next stage when current objectives are met

## Testing Guidance
${session.config?.outcomeGuidance || Session.DEFAULT_OUTCOME_GUIDANCE}

${session.config?.authenticationInstructions ? `## Authentication Instructions\n${session.config.authenticationInstructions}` : ""}

Be thorough but efficient. Focus on high-value targets first.`;
  }

  /**
   * Run the main agent loop
   */
  private async runAgentLoop(systemMessage: string, initialUserMessage: string): Promise<HITLAgentResult> {
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
        // Stop if: no tool calls made, or agent indicates completion
        const hasToolCalls = toolCalls && toolCalls.length > 0;
        if (!hasToolCalls) {
          continueLoop = false;
        }

        // Check for complete_testing tool call
        if (toolCalls?.some((tc: any) => tc.toolName === "complete_testing")) {
          continueLoop = false;
        }

      } catch (error) {
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
            content: `✓ ${existingMsg.content}`,
            result: (tr as any).output,
          });
        }
      }
    }
  }
}

/**
 * Create a new HITL agent
 */
export function createHITLAgent(config: HITLAgentConfig): HITLAgent {
  return new HITLAgent(config);
}

export type { HITLMode, HITLStage, PermissionTier, PendingApproval, ActionHistoryEntry };
