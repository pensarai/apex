/**
 * DriverModeAgent
 *
 * A wrapper around MetaVulnerabilityTestAgent that enables interactive driver mode.
 * Allows users to:
 * - Start agents with specific targets/objectives
 * - Inject user messages to redirect/pivot the agent
 * - Pause/resume execution
 * - Stream events back to UI
 */

import { EventEmitter } from 'events';
import type { AIModel } from '../../ai';
import { Session } from '../../session';
import type { PentestTarget } from '../attackSurfaceAgent/types';
import type { VulnerabilityClass } from '../orchestrator/types';
import {
  runMetaVulnerabilityTestAgent,
  type MetaVulnerabilityTestInput,
  type MetaVulnerabilityTestResult,
} from '../metaTestingAgent/metaVulnerabilityTestAgent';
import type { DisplayMessage } from '../../../tui/components/agent-display';

/**
 * Status of a driver mode agent
 */
export type DriverAgentStatus = 'idle' | 'running' | 'paused' | 'completed' | 'failed';

/**
 * Events emitted by the driver mode agent
 */
export interface DriverAgentEvents {
  'status-change': (status: DriverAgentStatus) => void;
  'message': (message: DisplayMessage) => void;
  'tool-call': (message: DisplayMessage) => void;
  'tool-result': (message: DisplayMessage) => void;
  'complete': (result: DriverAgentResult) => void;
  'error': (error: Error) => void;
}

/**
 * Result from driver mode agent completion
 */
export interface DriverAgentResult {
  vulnerabilitiesFound: boolean;
  findingsCount: number;
  pocPaths: string[];
  findingPaths: string[];
  summary: string;
  error?: string;
}

/**
 * Configuration for creating a driver mode agent
 */
export interface DriverModeAgentConfig {
  session: Session.SessionInfo;
  model: AIModel;
  /** Vulnerability class to focus on, defaults to 'generic' for broad testing */
  vulnerabilityClass?: VulnerabilityClass;
}

/**
 * DriverModeAgent class
 *
 * Wraps MetaVulnerabilityTestAgent for interactive use in driver mode.
 */
export class DriverModeAgent extends EventEmitter {
  private _status: DriverAgentStatus = 'idle';
  private abortController: AbortController | null = null;
  private pausePromise: Promise<void> | null = null;
  private pauseResolve: (() => void) | null = null;
  private messages: DisplayMessage[] = [];
  private userInjectedMessages: string[] = [];
  private readonly config: DriverModeAgentConfig;
  private currentTarget: PentestTarget | null = null;

  constructor(config: DriverModeAgentConfig) {
    super();
    this.config = config;
  }

  /**
   * Current status of the agent
   */
  get status(): DriverAgentStatus {
    return this._status;
  }

  /**
   * All messages from this agent's execution
   */
  get allMessages(): DisplayMessage[] {
    return [...this.messages];
  }

  /**
   * Set status and emit event
   */
  private setStatus(status: DriverAgentStatus): void {
    this._status = status;
    this.emit('status-change', status);
  }

  /**
   * Add a message and emit event
   */
  private addMessage(message: DisplayMessage): void {
    this.messages.push(message);
    this.emit('message', message);
  }

  /**
   * Start the agent with a specific target
   */
  async start(target: PentestTarget): Promise<void> {
    if (this._status === 'running') {
      throw new Error('Agent is already running');
    }

    this.currentTarget = target;
    this.setStatus('running');
    this.abortController = new AbortController();
    this.messages = [];

    // Add initial user message showing the target
    this.addMessage({
      role: 'user',
      content: `Testing target: ${target.target}\nObjective: ${target.objective}`,
      createdAt: new Date(),
    });

    try {
      const input: MetaVulnerabilityTestInput = {
        target: target.target,
        objective: target.objective,
        vulnerabilityClass: this.config.vulnerabilityClass || 'generic',
        authenticationInfo: target.authenticationInfo,
        authenticationInstructions: this.config.session.config?.authenticationInstructions,
        outcomeGuidance: this.config.session.config?.outcomeGuidance || Session.DEFAULT_OUTCOME_GUIDANCE,
        session: {
          id: this.config.session.id,
          rootPath: this.config.session.rootPath,
          findingsPath: this.config.session.findingsPath,
          logsPath: this.config.session.logsPath,
          pocsPath: this.config.session.pocsPath,
        },
        sessionConfig: {
          enableCvssScoring: this.config.session.config?.enableCvssScoring,
          cvssModel: this.config.session.config?.cvssModel,
        },
      };

      const result = await runMetaVulnerabilityTestAgent({
        input,
        model: this.config.model,
        abortSignal: this.abortController.signal,
        onStepFinish: async (step) => {
          // Check for pause
          if (this.pausePromise) {
            await this.pausePromise;
          }

          const { text, toolCalls, toolResults } = step;

          // Add text content
          if (text && text.trim()) {
            const lastMsg = this.messages[this.messages.length - 1];
            if (lastMsg && lastMsg.role === 'assistant') {
              // Append to existing assistant message
              this.messages[this.messages.length - 1] = {
                ...lastMsg,
                content: (lastMsg.content || '') + text,
              };
              this.emit('message', this.messages[this.messages.length - 1]);
            } else {
              this.addMessage({
                role: 'assistant',
                content: text,
                createdAt: new Date(),
              });
            }
          }

          // Add tool calls
          if (toolCalls && toolCalls.length > 0) {
            for (const tc of toolCalls) {
              const args = (tc as any).input as Record<string, unknown> | undefined;
              const toolDescription =
                typeof args?.toolCallDescription === 'string'
                  ? args.toolCallDescription
                  : tc.toolName;
              this.addMessage({
                role: 'tool',
                status: 'pending',
                toolCallId: tc.toolCallId,
                toolName: tc.toolName,
                content: toolDescription,
                args: args,
                createdAt: new Date(),
              });
            }
          }

          // Update tool results
          if (toolResults && toolResults.length > 0) {
            for (const tr of toolResults) {
              const msgIdx = this.messages.findIndex(
                (m) => m.role === 'tool' && (m as any).toolCallId === tr.toolCallId
              );
              if (msgIdx !== -1) {
                const existingMsg = this.messages[msgIdx] as DisplayMessage & { toolName?: string; toolCallId?: string };
                const description =
                  typeof existingMsg.content === 'string' &&
                  existingMsg.content !== existingMsg.toolName
                    ? existingMsg.content
                    : existingMsg.toolName || 'tool';
                this.messages[msgIdx] = {
                  ...existingMsg,
                  status: 'completed',
                  content: `✓ ${description}`,
                  result: (tr as any).output,
                };
                this.emit('message', this.messages[msgIdx]);
              }
            }
          }

          // Check for any injected user messages
          if (this.userInjectedMessages.length > 0) {
            const injected = this.userInjectedMessages.shift();
            if (injected) {
              this.addMessage({
                role: 'user',
                content: `[User Instruction] ${injected}`,
                createdAt: new Date(),
              });
            }
          }
        },
      });

      if (this._status !== 'paused') {
        this.setStatus('completed');
        const agentResult: DriverAgentResult = {
          vulnerabilitiesFound: result.vulnerabilitiesFound,
          findingsCount: result.findingsCount,
          pocPaths: result.pocPaths,
          findingPaths: result.findingPaths,
          summary: result.summary,
          error: result.error,
        };
        this.emit('complete', agentResult);
      }
    } catch (error) {
      if (this.abortController?.signal.aborted) {
        // Agent was stopped intentionally
        if (this._status !== 'paused') {
          this.setStatus('completed');
        }
      } else {
        this.setStatus('failed');
        this.emit('error', error instanceof Error ? error : new Error(String(error)));
      }
    }
  }

  /**
   * Inject a user message to redirect/pivot the agent
   * The message will be processed at the next step
   */
  async injectUserMessage(message: string): Promise<void> {
    if (this._status !== 'running' && this._status !== 'paused') {
      throw new Error('Cannot inject message when agent is not running');
    }

    this.userInjectedMessages.push(message);

    // Add the user message to display immediately
    this.addMessage({
      role: 'user',
      content: message,
      createdAt: new Date(),
    });

    // If paused, resume to process the message
    if (this._status === 'paused') {
      this.resume();
    }
  }

  /**
   * Pause execution (can be resumed)
   */
  pause(): void {
    if (this._status !== 'running') {
      return;
    }

    this.pausePromise = new Promise((resolve) => {
      this.pauseResolve = resolve;
    });
    this.setStatus('paused');
  }

  /**
   * Resume after pause
   */
  resume(): void {
    if (this._status !== 'paused') {
      return;
    }

    if (this.pauseResolve) {
      this.pauseResolve();
      this.pauseResolve = null;
      this.pausePromise = null;
    }
    this.setStatus('running');
  }

  /**
   * Stop completely
   */
  stop(): void {
    if (this.abortController) {
      this.abortController.abort();
    }
    if (this.pauseResolve) {
      this.pauseResolve();
    }
    this.setStatus('completed');
  }

}

/**
 * Create a new driver mode agent
 */
export function createDriverModeAgent(config: DriverModeAgentConfig): DriverModeAgent {
  return new DriverModeAgent(config);
}
